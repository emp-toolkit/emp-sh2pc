#ifndef _HMAC_H_
#define _HMAC_H_

#include <emp-tool/emp-tool.h>

#include <stdint.h>
#include <stdio.h>
#include <ctype.h>

#include "sha-256.h"

using namespace emp;
using namespace std; 

typedef struct EMP_HMAC_Context {
EMP_SHA256_CONTEXT shaContext;

Integer k_opad[SHA256_Message_Block_Size];
// unsigned char k_opad[USHA_Max_Message_Block_Size];
                        /* outer padding - key XORd with opad */
 // int 
  Integer Computed;
  // int 
  Integer Corrupted;
  int hashSize;
  int blockSize;

} EMP_HMAC_Context;




Integer HMAC_Reset(EMP_HMAC_Context *context, Integer* key, int key_len)
{
  /* inner padding - key XORd with ipad */
  Integer k_ipad[SHA256_Message_Block_Size];
  initIntegerArray(k_ipad, SHA256_Message_Block_Size, BYTE_BITS);
  /* temporary buffer when keylen > blocksize */
  Integer tempKey[SHA256HashSize];
  initIntegerArray(tempKey, SHA256HashSize, BYTE_BITS);

  initIntegerArray(context->k_opad, SHA256_Message_Block_Size, BYTE_BITS);
  // if (!context) return shaNull;
  context->Computed = Integer(INT_BITS, 0, PUBLIC);
  context->Corrupted = Integer(INT_BITS, shaSuccess, PUBLIC);

  /*
   * If key is longer than the hash blocksize,
   * reset it to key = HASH(key).
   */
  if (key_len > SHA256_Message_Block_Size) {
    EMP_SHA256_CONTEXT tcontext;
    SHA256_Reset(&tcontext);
    SHA256_Input(&tcontext, key, key_len);
    SHA256_Result(&tcontext, tempKey);
    // if (err != shaSuccess) return err;

    key = tempKey;
    key_len = SHA256HashSize;
  }
  int i;
  for (i = 0; i < key_len; i++) {
    k_ipad[i] = key[i] ^ Integer(BYTE_BITS, 0x36, PUBLIC);
    context->k_opad[i] = key[i] ^ Integer(BYTE_BITS, 0x5c, PUBLIC);
  }
  /* remaining pad bytes are '\0' XOR'd with ipad and opad values */
  for ( ; i < SHA256_Message_Block_Size; i++) {
    k_ipad[i] = Integer(BYTE_BITS, 0x36, PUBLIC);
    context->k_opad[i] = Integer(BYTE_BITS, 0x5c, PUBLIC);
  }

  /* perform inner hash */
  /* init context for 1st pass */
  // ret = SHA256Reset((SHA256Context*)&context->shaContext)
  
  Integer ret = SHA256_Reset(&context->shaContext) |
      /* and start with inner pad */
        SHA256_Input(&context->shaContext, k_ipad, SHA256_Message_Block_Size);
  return context->Corrupted = ret;
}



Integer HMAC_Input(EMP_HMAC_Context *context, Integer* text, int text_len)
{
  // if (!context) return shaNull;
  // if (context->Corrupted) return context->Corrupted;
  // if (context->Computed) return context->Corrupted = shaStateError;
  /* then text of datagram */
  return context->Corrupted =
    SHA256_Input(&context->shaContext, text, text_len);
}

Integer HMAC_Result(EMP_HMAC_Context *context, Integer* digest)
{
  // if (!context) return shaNull;
  // if (context->Corrupted) return context->Corrupted;
  // if (context->Computed) return context->Corrupted = shaStateError;

  /* finish up 1st pass */
  /* (Use digest here as a temporary buffer.) */
  Integer ret =
         SHA256_Result(&context->shaContext, digest) |
         /* perform outer SHA */
         /* init context for 2nd pass */
         SHA256_Reset(&context->shaContext) |

         /* start with outer pad */
         SHA256_Input(&context->shaContext, context->k_opad, SHA256_Message_Block_Size) |

         /* then results of 1st hash */
         SHA256_Input(&context->shaContext, digest, SHA256HashSize) |
         /* finish up 2nd pass */
         SHA256_Result(&context->shaContext, digest);

  context->Computed = Integer(INT_BITS, 1, PUBLIC);
  return context->Corrupted = ret;
}


#endif /* _HMAC_H_ */