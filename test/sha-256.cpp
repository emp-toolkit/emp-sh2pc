#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "emp-sh2pc/emp-sh2pc.h"
#include "sha-256.h"

/*
 * Private Functions
 */
Integer rotateInteger(int shift, Integer word) {
  Integer returnInteger = Integer(word.length, 0, PUBLIC);
  for(int i = 0; i < word.length; i++) {
    returnInteger[i] = word[(i+shift)%word.length];
  }
  return returnInteger;
}

Integer SHA256_SIGMA0_(Integer word) {
 return rotateInteger(2, word) ^ rotateInteger(13, word) ^ rotateInteger(22,word);
}

Integer SHA256_SIGMA1_(Integer word) {
 return rotateInteger(6, word) ^ rotateInteger(11, word) ^ rotateInteger(25,word);
}

Integer SHA256_sigma0(Integer word) {
 return rotateInteger(7, word) ^ rotateInteger(18, word) ^ SHA256_SHR( 3,word);
}

Integer SHA256_sigma1(Integer word) {
 return rotateInteger(17, word) ^ rotateInteger(19, word) ^ SHA256_SHR(10,word);
}

void initIntegerArray(Integer* intArray, int arraySize, int bitSize, int party=PUBLIC) {
  for(int i=0; i<arraySize; i++) {
    intArray[i] = Integer(bitSize, 0, party);
  }
}

/*
 * Public Functions
 */
Integer SHA256_Reset(EMP_SHA256_CONTEXT *context) {
    // Initial Hash Values in EMP Integers 
  // NOTE: EMP integers have to be within setup_plain_prot or else it segfaults!
  Integer H0[SHA256HashSize/4] = {
      Integer(32, "1779033703", PUBLIC),
      Integer(32, "3144134277", PUBLIC),
      Integer(32, "1013904242", PUBLIC),
      Integer(32, "2773480762", PUBLIC),
      Integer(32, "1359893119", PUBLIC),
      Integer(32, "2600822924", PUBLIC),
      Integer(32, "528734635", PUBLIC),
      Integer(32, "1541459225", PUBLIC)
  };
  if (!context) return Integer(INT_BITS, shaNull, PUBLIC);

  // Change to initArray DEBUG
  for(int i=0; i<SHA256_Message_Block_Size; i++) {
    context->Message_Block[i] = Integer(MESSAGE_BLOCK_BITS, 0, PUBLIC);
  }

  context->Length_High = context->Length_Low = Integer(LENGTH_BITS, 0, PUBLIC);
  context->Message_Block_Index = Integer(MESSAGE_BLOCK_INDEX_BITS, 0, PUBLIC);
  context->Intermediate_Hash[0] = H0[0];
  context->Intermediate_Hash[1] = H0[1];
  context->Intermediate_Hash[2] = H0[2];
  context->Intermediate_Hash[3] = H0[3];
  context->Intermediate_Hash[4] = H0[4];
  context->Intermediate_Hash[5] = H0[5];
  context->Intermediate_Hash[6] = H0[6];
  context->Intermediate_Hash[7] = H0[7];
  for(int i = 8; i < SHA256HashSize/4; i++) {
    context->Intermediate_Hash[i] = Integer(INTERMEDIATE_HASH_BITS, 0, PUBLIC);
  }
  context->Computed  = Integer(INT_BITS, 0, PUBLIC);
  context->Corrupted = Integer(INT_BITS, shaSuccess, PUBLIC);

  return Integer(INT_BITS, shaSuccess, PUBLIC);
}

Integer SHA256_AddLength(EMP_SHA256_CONTEXT *context, unsigned int length) {
  Integer addTemp = context->Length_Low;
  context->Length_Low = context->Length_Low + Integer(LENGTH_BITS, length, PUBLIC);
  context->Length_High = context->Length_High.select((context->Length_Low < addTemp), (context->Length_High + Integer(LENGTH_BITS, 1, PUBLIC)));

  Integer result = context->Corrupted.select(context->Length_High == Integer(LENGTH_BITS, 0, PUBLIC), Integer(LENGTH_BITS, shaInputTooLong, PUBLIC));  
  context->Corrupted = context->Corrupted.select(context->Length_Low < addTemp, result);

  return context->Corrupted;
}

static void SHA256_ProcessMessageBlock(EMP_SHA256_CONTEXT *context) {
  static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };

  // Convert K
  Integer EMP_K[64];

  for (int i = 0; i < 64; i++) {
    EMP_K[i] = Integer(INTERMEDIATE_HASH_BITS, K[i], PUBLIC);
  }

  int        t, t4;                   /* Loop counter */
  // 32 bits
  Integer   temp1, temp2;            /* Temporary word value */
  Integer   W[SHA256_Message_Block_Size];                   /* Word sequence */
  // 32 bits
  Integer   A, B, C, D, E, F, G, H;  /* Word buffers */

  /*
  * Initialize the first 16 words in the array W
  */
  Integer Resized_Message_Block[SHA256_Message_Block_Size];
  for(int i = 0; i < SHA256_Message_Block_Size; i++) {
    Resized_Message_Block[i] = context->Message_Block[i];
    Resized_Message_Block[i].resize(INTERMEDIATE_HASH_BITS, false);
  }
  
  for (t = t4 = 0; t < 16; t++, t4 += 4) {
    W[t] = (Resized_Message_Block[t4] << 24) |
            (Resized_Message_Block[t4+1] << 16) |
            (Resized_Message_Block[t4+2] << 8) |
            (Resized_Message_Block[t4+3]);
  }
 
  for (t = 16; t < 64; t++) {
    W[t] = SHA256_sigma1(W[t-2]) + W[t-7] + SHA256_sigma0(W[t-15]) + W[t-16];
    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];
    F = context->Intermediate_Hash[5];
    G = context->Intermediate_Hash[6];
    H = context->Intermediate_Hash[7];
  }
  for (t = 0; t < 64; t++) {
    temp1 = H + SHA256_SIGMA1_(E) + SHA_Ch(E,F,G) + EMP_K[t] + W[t];
    temp2 = SHA256_SIGMA0_(A) + SHA_Maj(A,B,C);
    H = G;
    G = F;
    F = E;
    E = D + temp1;
    D = C;
    C = B;
    B = A;
    A = temp1 + temp2;
  }
  context->Intermediate_Hash[0] = context->Intermediate_Hash[0] + A;
  context->Intermediate_Hash[1] = context->Intermediate_Hash[1] + B;
  context->Intermediate_Hash[2] = context->Intermediate_Hash[2] + C;
  context->Intermediate_Hash[3] = context->Intermediate_Hash[3] + D;
  context->Intermediate_Hash[4] = context->Intermediate_Hash[4] + E;
  context->Intermediate_Hash[5] = context->Intermediate_Hash[5] + F;
  context->Intermediate_Hash[6] = context->Intermediate_Hash[6] + G;
  context->Intermediate_Hash[7] = context->Intermediate_Hash[7] + H;
  context->Message_Block_Index = Integer(MESSAGE_BLOCK_INDEX_BITS, 0, PUBLIC);
}

void deepCopyContext(EMP_SHA256_CONTEXT* context, EMP_SHA256_CONTEXT* contextCopy) {
  for(int i = 0; i<SHA256HashSize/4; i++) {
    contextCopy->Intermediate_Hash[i] = context->Intermediate_Hash[i];
  }
  contextCopy->Length_High = context->Length_High;
  contextCopy->Length_Low = context->Length_Low;
  contextCopy->Message_Block_Index = context->Message_Block_Index;

  for(int i = 0; i<SHA256_Message_Block_Size; i++) {
    contextCopy->Message_Block[i] = context->Message_Block[i];
  }
  contextCopy->Computed = context->Computed;
  contextCopy->Corrupted = context->Corrupted;
  return;
}

void selectContext(EMP_SHA256_CONTEXT* context, EMP_SHA256_CONTEXT* tempContext, Bit condition) {
  for(int i = 0; i<SHA256HashSize/4; i++) {
    context->Intermediate_Hash[i] = context->Intermediate_Hash[i].select(condition, tempContext->Intermediate_Hash[i]);
  }
  context->Length_High = context->Length_High.select(condition, tempContext->Length_High);
  context->Length_Low = context->Length_Low.select(condition, tempContext->Length_Low);
  context->Message_Block_Index = context->Message_Block_Index.select(condition, tempContext->Message_Block_Index);

  for(int i = 0; i<SHA256_Message_Block_Size; i++) {
    context->Message_Block[i] = context->Message_Block[i].select(condition, tempContext->Message_Block[i]);
  }
  context->Computed = context->Computed.select(condition, tempContext->Computed );
  context->Corrupted = context->Corrupted.select(condition, tempContext->Corrupted);
  return;
}

Integer SHA256_Input(EMP_SHA256_CONTEXT *context, Integer *message_array, unsigned int length) {
  if (!context) return Integer(INT_BITS, shaNull, PUBLIC);
  if (!length) return Integer(INT_BITS, shaSuccess, PUBLIC); // 
  if (!message_array) return Integer(INT_BITS, shaNull, PUBLIC);

  context->Corrupted = context->Corrupted.select(context->Computed > Integer(INT_BITS, 0, PUBLIC), Integer(INT_BITS, shaStateError, PUBLIC));
  
  while (length--) {
    for (int i = 0; i < SHA256_Message_Block_Size; i++) {   
       context->Message_Block[i] = 
         context->Message_Block[i].select(Integer(INT_BITS, i, PUBLIC) == context->Message_Block_Index, *message_array);
    }
    context->Message_Block_Index = context->Message_Block_Index + Integer(MESSAGE_BLOCK_INDEX_BITS, 1, PUBLIC);
    Integer addLengthResult = SHA256_AddLength(context, 8);
    EMP_SHA256_CONTEXT tempContext;
    deepCopyContext(context, &tempContext);
  
    SHA256_ProcessMessageBlock(&tempContext); // Can we unconditionally run this? Do we just have to reveal this conditional?
    selectContext(context, &tempContext, (addLengthResult == Integer(INT_BITS, shaSuccess, PUBLIC)) & 
                  (context->Message_Block_Index == Integer(MESSAGE_BLOCK_INDEX_BITS, SHA256_Message_Block_Size, PUBLIC)));

    message_array++;
  }
  return context->Corrupted;
}

void SHA256_PadMessage(EMP_SHA256_CONTEXT *context, Integer Pad_Byte) {
  Bit ifCondition = context->Message_Block_Index >= Integer(INT_BITS, SHA256_Message_Block_Size-8, PUBLIC);
  for (int i = 0; i < SHA256_Message_Block_Size; i++) {
      context->Message_Block[i] = 
        context->Message_Block[i].select(Integer(INT_BITS, i, PUBLIC) == context->Message_Block_Index, Pad_Byte);
  }
  context->Message_Block_Index = context->Message_Block_Index + Integer(MESSAGE_BLOCK_INDEX_BITS, 1, PUBLIC);
  EMP_SHA256_CONTEXT ifContextObj;
  EMP_SHA256_CONTEXT* ifContext = &ifContextObj;
  deepCopyContext(context, ifContext);

  for (int i = 0; i < SHA256_Message_Block_Size; i++) {
    Bit messageBlockCondition = ifContext->Message_Block_Index == Integer(MESSAGE_BLOCK_INDEX_BITS, i, PUBLIC);
    Bit blockCondition = ifContext->Message_Block_Index < Integer(MESSAGE_BLOCK_INDEX_BITS, SHA256_Message_Block_Size, PUBLIC);
    Bit overallCondition = messageBlockCondition & blockCondition;
    ifContext->Message_Block[i] = 
      ifContext->Message_Block[i].select(overallCondition, Integer(MESSAGE_BLOCK_BITS, 0, PUBLIC));
    ifContext->Message_Block_Index = 
      ifContext->Message_Block_Index.select(overallCondition, ifContext->Message_Block_Index + Integer(MESSAGE_BLOCK_INDEX_BITS, 1, PUBLIC));
  }
  SHA256_ProcessMessageBlock(ifContext);
  
  selectContext(context, ifContext, ifCondition);
  
  for (int i = 0; i < SHA256_Message_Block_Size; i++) {
    Integer maxIndex = Integer(MESSAGE_BLOCK_INDEX_BITS, SHA256_Message_Block_Size-8, PUBLIC);
    Bit startCondition = Integer(MESSAGE_BLOCK_INDEX_BITS, i , PUBLIC) >= context->Message_Block_Index;
    Bit blockCondition = context->Message_Block_Index < maxIndex;
    Bit condition = startCondition & blockCondition;

    context->Message_Block[i] = 
      context->Message_Block[i].select(condition, Integer(MESSAGE_BLOCK_BITS, 0, PUBLIC));
    context->Message_Block_Index = 
      context->Message_Block_Index.select(condition, context->Message_Block_Index + Integer(MESSAGE_BLOCK_INDEX_BITS, 1, PUBLIC));
  }

  context->Message_Block[56] = context->Length_High >> 24;
  context->Message_Block[57] = context->Length_High >> 16;
  context->Message_Block[58] = context->Length_High >> 8;
  context->Message_Block[59] = context->Length_High;
  context->Message_Block[60] = context->Length_Low >> 24;
  context->Message_Block[61] = context->Length_Low >> 16;
  context->Message_Block[62] = context->Length_Low >> 8;
  context->Message_Block[63] = context->Length_Low;
  SHA256_ProcessMessageBlock(context);
  return;
}


void SHA256_Finalize(EMP_SHA256_CONTEXT *context, Integer Pad_Byte) {
  int i;
  SHA256_PadMessage(context, Pad_Byte);
  for (i = 0; i < SHA256_Message_Block_Size; ++i) {
    context->Message_Block[i] = Integer(MESSAGE_BLOCK_BITS, 0, PUBLIC);
  }

  // TODO: Do we need to do this?
  context->Length_High = Integer(LENGTH_BITS, 0, PUBLIC);
  context->Length_Low = Integer(LENGTH_BITS, 0, PUBLIC);
  context->Computed = Integer(INT_BITS, 1, PUBLIC);
  return;
}


Integer SHA256_Result(EMP_SHA256_CONTEXT *context, Integer *Message_Digest) {
  if (!context) return Integer(INT_BITS, shaNull, PUBLIC);
  if (!Message_Digest) return Integer(INT_BITS, shaNull, PUBLIC);
  EMP_SHA256_CONTEXT tempContext; 
  deepCopyContext(context, &tempContext);
  SHA256_Finalize(&tempContext, Integer(BYTE_BITS, 0x80, PUBLIC));
  selectContext(context, &tempContext, context->Computed == Integer(INT_BITS, 0, PUBLIC));

  for (int i = 0; i < SHA256HashSize; i++) {
    Message_Digest[i] =  (context->Intermediate_Hash[i>>2] >> 8 * ( 3 - ( i & 0x03 ) ));
  }
  return Integer(INT_BITS, shaSuccess, PUBLIC);
}


// bool compareHash(uint8_t* sslHash, Integer* empHash) {
//   for (int i =0; i < SHA256HashSize; i++) {
//     bitset<8> sslBitset(sslHash[i]);
//     for (int j = 7; j >= 0; j--) {
//       if(empHash[i][j].reveal() != sslBitset[j]) {
//         cout << endl << "FALSE" << endl;
//         return false;
//       }
//     }
//   }
//   cout << endl << "TRUE" << endl;
//   return true;
// }


// void testInput(char* str, int length) {

//   /* 2 PC */
//   EMP_SHA256_CONTEXT sha;
//   Integer err = SHA256_Reset(&sha);

//   Integer input[length];
//   for (int i = 0; i < length; i++) {
//     input[i] = Integer(8, str[i], ALICE);
//   }
//   err = SHA256_Input(&sha, input, length);
//   Integer Message_Digest_Buf[SHA256HashSize];
//   Integer *Message_Digest = Message_Digest_Buf;

//   err = SHA256_Result(&sha, Message_Digest);

//   /* OpenSSL */
//   uint8_t digest[32];
//   Hash::hash_once(&digest, str, length);
//   bool success = compareHash(digest, Message_Digest);
//   if(!success) {
//     cout << "Failed test with str: " << str << endl;
//   }
// }

// int main(int argc, char** argv) {
//   int port, party;
//   parse_party_and_port(argv, &party, &port);
//   char* inputVal = argv[3];
//   int inputLength = atoi(argv[4]);
//   NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);
//   setup_semi_honest(io, party);
//   testInput(inputVal, inputLength);

//   delete io;
// }



