/******************************************************************************
* Copyright (c) 2000-2018 Ericsson Telecom AB
* All rights reserved. This program and the accompanying materials
* are made available under the terms of the Eclipse Public License v2.0
* which accompanies this distribution, and is available at
* https://www.eclipse.org/org/documents/epl-2.0/EPL-2.0.html
*
* Contributors:
* Endre Kulcsar
* Gabor Szalai
******************************************************************************/
//
//  File:     L2TP_EncDec.cc
//  Rev:      R2A
//  Prodnr:   CNL 113 603
//  Reference: RFC 2661
//
///////////////////////////////////////////////////////////////////////////////

#include "L2TP_Types.hh"

#include <openssl/md5.h>
#include <time.h>
 
namespace L2TP__Types {

#define CTRL_MSG_HDR_LENGTH 20
// Length of L2TP control message header (Length,Nr and Ns fields are mandatory) + Length of Message Type AVP


// calculates 16 bit MD5 message digest
unsigned char * calc_MD5(OCTETSTRING& pl_input, int pl_size, unsigned char * output)
   {     
      MD5(pl_input,(size_t) pl_size,output);
      return output;   
   }

OCTETSTRING enc__PDU__L2TP(const PDU__L2TP& pdu)
{
    if (TTCN_Logger::log_this_event(TTCN_DEBUG)) {
	TTCN_Logger::begin_event(TTCN_DEBUG);
	TTCN_Logger::log_event("Encoding PDU_L2TP: ");
	pdu.log();
	TTCN_Logger::end_event();
    }

    TTCN_Buffer buf;
    pdu.encode(PDU__L2TP_descr_, buf, TTCN_EncDec::CT_RAW);
    
    // ret_val is the RAW encoded PDU without any AVP Hiding
    // if there are no H_BITs equal to 1 this will be returned from enc__PDU__L2TP             
    OCTETSTRING ret_val(buf.get_len(), buf.get_data());
                 
    // only control msgs use hiding (tBit = 1)
    const unsigned char *T_BIT = pdu.header().tBit();
    if (*T_BIT  && (ret_val.lengthof() >= CTRL_MSG_HDR_LENGTH))  // if ctrl message and not ZLB    
      {          
        OCTETSTRING ret_val_ctrl_msg = substr(ret_val,0,CTRL_MSG_HDR_LENGTH); // copy original msg header
           
        const unsigned char * avp_length;
        unsigned int avp_length_int;
        const unsigned char * avp_type;
        //unsigned int avp_type_int;
        unsigned int index = CTRL_MSG_HDR_LENGTH; 
        //unsigned int index_rv = CTRL_MSG_HDR_LENGTH; 
        bool H_BIT;       
        OCTETSTRING AVP_TYPE;
        OCTETSTRING AVP_HEADER;
        OCTETSTRING AVP_VALUE; 
        OCTETSTRING AVP_LENGTH;                               
        const unsigned char header_mask[2] = {0xfc, 0x00};
        unsigned char avp_hidden_length[2];       
        srand((unsigned)time(0)); 

        while (index < buf.get_len() )
          { 
            avp_length = ((const unsigned char *)ret_val) + index;                                             
            H_BIT = ((avp_length[0] & 0x40) >> 6); // H_BIT = 1 -> hiding is needed for this AVP                              
            avp_length_int = ((avp_length[0] & 0x03) << 8) + avp_length[1]; // length of AVP
            AVP_LENGTH = int2oct(avp_length_int-6,2);                       
            AVP_HEADER = substr(ret_val,index,6);                 
            avp_type = ((const unsigned char *)ret_val)+ index+4;
            AVP_TYPE = OCTETSTRING(2,avp_type);
            AVP_VALUE = substr(ret_val,index+6,avp_length_int-6);  
            OCTETSTRING AVP_VALUE_HIDDEN(0,NULL);                                 
            //avp_type_int = (avp_type[0] << 8) + avp_type[1];
            unsigned int index_rv = CTRL_MSG_HDR_LENGTH;
                                      
            if (H_BIT == TRUE)   // hidden AVP is needed
              {                             
                bool bound_flag = FALSE;                                                    
                OCTETSTRING random_vector;
                
                // find random vector "most closely preceding"
                while (index_rv < index )
                 { 
                   const unsigned char *avp_length_find_rv = ((const unsigned char *)ret_val)+index_rv;
                   unsigned int avp_length_int_find_rv = ((avp_length_find_rv[0] & 0x03) << 8) + avp_length_find_rv[1]; // length of AVP 
                           
                   const unsigned char *avp_type_find_rv = ((const unsigned char *)ret_val) + index_rv+4;
                   unsigned int avp_type_int_find_rv = (avp_type_find_rv[0] << 8) + avp_type_find_rv[1];
                                                       
                   if (avp_type_int_find_rv == 36)  // if AVP's Attr type is rand vect   
                     {
                       random_vector = substr(ret_val,index_rv+6,avp_length_int_find_rv-6);
                       bound_flag = TRUE;                
                     } 
                       
                   index_rv = index_rv + avp_length_int_find_rv; // points to start of next AVP in original stream
                 } 
                                          
                if (bound_flag == FALSE)    // random_vector.is_bound() == NULL 
                   {TTCN_error("%s","No Random Vector AVP present");}  // Error: No Random Vector AVP before Hidden AVP!                      
                                           
                // Calculate RANDOM_PADDING needed for HIDDEN_AVP_SUBFORMAT
                int random = rand();  
                OCTETSTRING HIDDEN_AVP_SUBFORMAT;               
                if ( (random % (tsp__Max__Random__Padding__Length+1)) == 0 )
                  {   
                    HIDDEN_AVP_SUBFORMAT = AVP_LENGTH + AVP_VALUE;  
                  }
                else   
                  {            
                    OCTETSTRING RANDOM_PADDING(int2oct(0,random % (tsp__Max__Random__Padding__Length+1)));                            
                    HIDDEN_AVP_SUBFORMAT = AVP_LENGTH + AVP_VALUE + RANDOM_PADDING;
                  }  
                            
                // AVP padded to exact multiple of 16   
                int avp_padding_length = 16 -(HIDDEN_AVP_SUBFORMAT.lengthof() % 16 );
                unsigned char padding[avp_padding_length];
                for(int i = 0; i < avp_padding_length; i++) 
                  {padding[i] = 0x00;}                         
                OCTETSTRING AVP_PADDING = OCTETSTRING(avp_padding_length,padding);                                                               
                OCTETSTRING AVP_VALUE_PADDED = HIDDEN_AVP_SUBFORMAT + AVP_PADDING;  
                                                  
                // CONCATENATION is input into HIDE procedure                                                                
                OCTETSTRING CONCATENATION =  AVP_TYPE + tsp__L2TP__SharedSecret + random_vector;
                     
                // HIDE PROCEDURE
                 OCTETSTRING b;
                 OCTETSTRING c;  
                 unsigned char MD5_value[16];                            
                 for (int j = 0; j < (AVP_VALUE_PADDED.lengthof()) ; j=j+16) 
                   {      
                     b = OCTETSTRING(16,(const unsigned char *)calc_MD5(CONCATENATION,CONCATENATION.lengthof(),MD5_value));                              
                     c = ((substr(AVP_VALUE_PADDED,j ,16 )) ^ b);                                                          
                     CONCATENATION = tsp__L2TP__SharedSecret + c;                              
                     AVP_VALUE_HIDDEN = AVP_VALUE_HIDDEN + c;      
                   } 
                                                        
                 // modify length field in AVP_HEADER to actual length of hidden AVP               
                 unsigned int avp_hidden_length_int = 6 + AVP_VALUE_HIDDEN.lengthof();           
                 avp_hidden_length[0] = (avp_hidden_length_int & 0x0300)>> 8; 
                 avp_hidden_length[1] = (avp_hidden_length_int & 0xff);  
                 unsigned char* avp_header2 = (unsigned char*)(const unsigned char*)AVP_HEADER; 
                 avp_header2[0] &= header_mask[0];
                 avp_header2[1] &= header_mask[1];              
                 avp_header2[0] |= avp_hidden_length[0];
                 avp_header2[1] |= avp_hidden_length[1]; 
                           
                 ret_val_ctrl_msg = ret_val_ctrl_msg  + AVP_HEADER + AVP_VALUE_HIDDEN;  // Add new hidden AVP                                                                                    
               }
             else  // original (not hidden) AVP is used because for this AVP H_BIT == FALSE
               {
                 ret_val_ctrl_msg = ret_val_ctrl_msg + substr(ret_val,index,avp_length_int);                 
               }              
                index = index + avp_length_int; // points to start of next AVP in original stream
           } // end of while (index < buf.get_len() )
                       
          ret_val = ret_val_ctrl_msg;     
        }  // end of  if (*T_BIT)
          
   //fill in true length of complete PDU if lengthValue field is present
   if (pdu.header().lengthValue().ispresent())
    {           
      unsigned int PDU_SIZE_INT = ret_val.lengthof();
      unsigned char PDU_SIZE_CHAR[2]; 
      PDU_SIZE_CHAR[0] = (PDU_SIZE_INT & 0xff00) >> 8;
      PDU_SIZE_CHAR[1] = (PDU_SIZE_INT & 0xff );
     
      OCTETSTRING PDU_SIZE_OCTETSTRING(2, PDU_SIZE_CHAR);
      
      ret_val = substr(ret_val,0,2) + PDU_SIZE_OCTETSTRING + substr(ret_val,4,PDU_SIZE_INT-4);   
    } 
        
    if (TTCN_Logger::log_this_event(TTCN_DEBUG)) {
	TTCN_Logger::begin_event(TTCN_DEBUG);
	TTCN_Logger::log_event("Encoded PDU_L2TP: ");
	ret_val.log();
	TTCN_Logger::end_event();
    }    
    return ret_val;
}

PDU__L2TP dec__PDU__L2TP(const OCTETSTRING& stream)
{
    if (TTCN_Logger::log_this_event(TTCN_DEBUG)) {
	TTCN_Logger::begin_event(TTCN_DEBUG);
	TTCN_Logger::log_event("Decoding PDU_L2TP: ");
	stream.log();
	TTCN_Logger::end_event();
    }
      TTCN_Buffer buf;   

    // if control message check AVPs whether hiding was used
    if  ((((((const unsigned char *)stream)[0]) & 0x80) == 0x80)  && (stream.lengthof() >= CTRL_MSG_HDR_LENGTH))   // if control message and not ZLB
      {      
       OCTETSTRING stream_ctrl_msg = substr(stream,0,CTRL_MSG_HDR_LENGTH); // copy original msg header              
       unsigned int index = CTRL_MSG_HDR_LENGTH; 
       //unsigned int index_rv = CTRL_MSG_HDR_LENGTH; 
       const unsigned char * avp_length;       
       unsigned avp_length_int;
       //unsigned avp_length_int_orig;      
       bool H_BIT;    
       while (index < (unsigned int)stream.lengthof() )
         {  
           avp_length = ((const unsigned char *)stream) + index;  
           H_BIT = ((avp_length[0] & 0x40) >> 6); //if H_BIT = 1 -> hiding was used for this AVP          
           avp_length_int = ((avp_length[0] & 0x03) << 8) + avp_length[1]; // length of AVP 
           //avp_length_int_orig = avp_length_int;
           OCTETSTRING AVP_HEADER = substr(stream,index,6); 
           const unsigned char header_mask[2] = {0xfc, 0x00};
           unsigned char* avp_hidden_length;    //[2];
           unsigned int index_rv = CTRL_MSG_HDR_LENGTH;           
                                           
           if (H_BIT == TRUE)  //  hiding was used for this AVP
             {                                
              bool bound_flag = FALSE;                                                    
              OCTETSTRING random_vector;
                
              // find random vector "most closely preceding"  
              OCTETSTRING HIDDEN_AVP_SUBFORMAT(0,NULL); 
              while (index_rv < index )
                { 
                  const unsigned char *avp_length_find_rv = ((const unsigned char *)stream)+index_rv;
                  unsigned int avp_length_int_find_rv = ((avp_length_find_rv[0] & 0x03) << 8) + avp_length_find_rv[1]; // length of AVP   
                                  
                  const unsigned char *avp_type_find_rv = ((const unsigned char *)stream) + index_rv+4;
                  unsigned int avp_type_int_find_rv = (avp_type_find_rv[0] << 8) + avp_type_find_rv[1];
                                                                                                
                  if (avp_type_int_find_rv == 36)  // if AVP's Attr type is rand vect   
                    {
                      random_vector = substr(stream,index_rv+6,avp_length_int_find_rv-6);   
                      bound_flag = TRUE;                
                    }                                                                              
                   index_rv = index_rv + avp_length_int_find_rv; // points to start of next AVP in original stream                  
                 }                  
               if (bound_flag == FALSE)    
                  {TTCN_error("%s","No Random Vector AVP present");}  // Error: No Random Vector AVP before Hidden AVP! 
 
               // CONCATENATION is input into HIDE procedure                                                                
               OCTETSTRING CONCATENATION;                                 
               const unsigned char *avp_type = ((const unsigned char *)stream) + index+4; //type of AVP                
               OCTETSTRING AVP_TYPE = OCTETSTRING(2,avp_type);
               unsigned char MD5_value[16];                 
               OCTETSTRING b;
               OCTETSTRING p;                                                                            
               unsigned int j = index + avp_length_int-32;
                                            
               while(j >= (index + 6))  
                {                                                                                                                  
                  CONCATENATION = tsp__L2TP__SharedSecret + substr(stream,j,16);                                                                                                                               
                  b = OCTETSTRING(16,(const unsigned char *)calc_MD5(CONCATENATION,CONCATENATION.lengthof(),MD5_value));                                                                                     
                  p = b ^ substr(stream,j + 16,16);                                                   
                  HIDDEN_AVP_SUBFORMAT = p + HIDDEN_AVP_SUBFORMAT;                              
                  j = j-16;         
                }                     
                   CONCATENATION = AVP_TYPE + tsp__L2TP__SharedSecret + random_vector;                   
                   b = OCTETSTRING(16,(const unsigned char *)calc_MD5(CONCATENATION,CONCATENATION.lengthof(),MD5_value));                          
                   p = b ^ substr(stream,index + 6,16); 
                   HIDDEN_AVP_SUBFORMAT = p + HIDDEN_AVP_SUBFORMAT;  
                                                                                                                      
                 // modify length field in AVP_HEADER to actual length of hidden AVP                              
                 avp_hidden_length = (unsigned char*)(const unsigned char*)HIDDEN_AVP_SUBFORMAT;
                 unsigned int avp_length_int_unhidden = 6 + (((avp_hidden_length[0] & 0x03) << 8) + avp_hidden_length[1]); // complete length of AVP  
                 unsigned int avp_length_int_unhidden_copy = avp_length_int_unhidden;                                
                 unsigned char* avp_header2 = (unsigned char*)(const unsigned char*)AVP_HEADER;                                     
                 avp_header2[0] &= header_mask[0];
                 avp_header2[1] &= header_mask[1];                  
                 avp_header2[0] |= ((avp_length_int_unhidden & 0x0300)>> 8); 
                 avp_header2[1] |= (avp_length_int_unhidden & 0xff);  
                                                                            
                 stream_ctrl_msg = stream_ctrl_msg + AVP_HEADER + substr(HIDDEN_AVP_SUBFORMAT,2,avp_length_int_unhidden_copy-6);  
                                                     
             } // end of if (H_BIT == TRUE)
           else  // original (not hidden) AVP is used because for this AVP H_BIT == FALSE
             {
               stream_ctrl_msg = stream_ctrl_msg + substr(stream,index,avp_length_int);                               
             }                                                                          
            index = index + avp_length_int;        
         } // end of while                    
          buf.put_os(stream_ctrl_msg); 
      } // end of  if control message
      
    else  // user data message
      {
          buf.put_os(stream);      
      }
              
    PDU__L2TP ret_val;
    ret_val.decode(PDU__L2TP_descr_, buf, TTCN_EncDec::CT_RAW);

    if (TTCN_Logger::log_this_event(TTCN_DEBUG)) {
	TTCN_Logger::begin_event(TTCN_DEBUG);
	TTCN_Logger::log_event("Decoded PDU_L2TP: ");
	ret_val.log();
	TTCN_Logger::end_event();
    }    
    return ret_val;
  }  // end of function dec__PDU__L2TP

}  // end of module
