#include <emp-tool/emp-tool.h>
#include "emp-tool/utils/hash.h"
#include "emp-sh2pc/emp-sh2pc.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <ctype.h>

#include "hmac.h"

using namespace emp;
using namespace std; 


static int SN_LENGTH = 12; 
static int CID_LENGTH = 4;
static int DATA_LENGTH = SN_LENGTH + CID_LENGTH;
static int KEY_LENGTH = 32; 
static int RANDOM_LENGTH = 96; 
static int RPRIME_LENGTH = 32;
static int TOKEN_LENGTH = 1;


/* * * * * * * * * * * * 
 *  D E B U G G I N G  *
 * * * * * * * * * * * */
void printInteger(Integer intToPrint, int bitSize) {
  for (int i = bitSize -1; i >= 0; i--) {
    cout << intToPrint[i].reveal();
  }
  return;
}

void printIntegerArray(Integer* intToPrint, int arraySize, int bitSize) {
  for(int i = 0; i < arraySize; i++) {
    printInteger(intToPrint[i], bitSize);
    cout << ", ";
  }
  cout << endl;
  return;
}

static int ALL = 0;
static int Msg_Block = 1;
static int Msg_Block_Index = 2;
static int Msg_Intermediate_Hash = 4;

void printContext(EMP_SHA256_CONTEXT *context, int flag, string debugMsg) {
  cout << debugMsg << endl;
  if (flag == ALL || flag == Msg_Intermediate_Hash) {
    cout << "Interemdiate Hash " << endl;
    printIntegerArray(context->Intermediate_Hash, INTERMEDIATE_HASH_LEN, 32);
  }
  if (flag == ALL) {
    cout << "Length high " << endl;
    printInteger(context->Length_High, LENGTH_BITS);
    cout << endl;
  }
  if (flag == ALL) {
    cout << "Length low " << endl;
    printInteger(context->Length_Low, LENGTH_BITS);
    cout << endl;
  }  
  if (flag == ALL || flag == Msg_Block_Index) { 
    cout << "Message block index " << endl;
    printInteger(context->Message_Block_Index, MESSAGE_BLOCK_INDEX_BITS);
    cout << endl;
  }
  if (flag == ALL || flag == Msg_Block) {
    cout << "Message block contents " << endl;
    printIntegerArray(context->Message_Block, SHA256_Message_Block_Size, MESSAGE_BLOCK_BITS);
  }
}

/* * * * * * * * * *
 *  T E S T I N G  *
 * * * * * * * * * */
void printHash(Integer* Message_Digest) {
  cout << "Printing output hash: " << endl;
  for (int i =0; i < SHA256HashSize; i++) {
    for (int j =7; j >= 0; j--) {
      cout << Message_Digest[i][j].reveal();
    }
  }
  cout << endl;
}

void print_uint8_t(uint8_t n) {
  bitset<8> x(n);
  cout << x;
}

void printSSLHash(uint8_t* sslHash, int arraySize) {
  for(int i = 0; i < arraySize; i++) {
    print_uint8_t(sslHash[i]);
    cout << ", ";
  }
  cout << endl;
  return;
}

bool compareHash(uint8_t* sslHash, Integer* empHash) {
  for (int i =0; i < SHA256HashSize; i++) {

    //cout << "enters here? :" << i << endl;
    //cout << "HASH SIZE :" << SHA256HashSize << endl;
    bitset<8> sslBitset(sslHash[i]);
    for (int j = 7; j >= 0; j--) {
      //cout << "j equals :" << j << endl;
      //cout << empHash[i][j].reveal() << endl;
      //cout << sslBitset[j] << endl;
      if(empHash[i][j].reveal() != sslBitset[j]) {
        cout << endl << "FALSE" << endl;
        return false;
      }
    }
    //cout <<  sslBitset << ", ";
  }
  cout << endl << "TRUE" << endl;
  return true;
}

Integer* runHmac(Integer* key, int key_length,Integer* message, int message_length) {

  static Integer digest_buf[SHA256HashSize];
  Integer* digest = digest_buf;
  EMP_HMAC_Context context;
  // HMAC_Reset(&context, intKey, key_length);
  // HMAC_Input(&context, intMsg, message_length);
  HMAC_Reset(&context, key, key_length);
  HMAC_Input(&context, message, message_length);
  HMAC_Result(&context, digest);
  printHash(digest);

  Integer* digest_ptr = new Integer(); 
  digest_ptr = digest;

  return digest_ptr;
}


void xor_reconstruct(char* int1, char* int2, int output_length, Integer* output) {
  Integer intMsg1[output_length];
  for (int i = 0; i < output_length; i++) {
    intMsg1[i] = Integer(8, int1[i], ALICE);
  }
  Integer intMsg2[output_length];
  for (int i = 0; i < output_length; i++) {
    intMsg2[i] = Integer(8, int2[i], BOB);
  }

  for (int i = 0; i < output_length; i++) {
    output[i] = intMsg1[i] ^ intMsg2[i]; 
  }

  return;

}

int main(int argc, char** argv) {

  int port, party;
  parse_party_and_port(argv, &party, &port);

  char* k_share = argv[3];
  char* p = argv[4];
  char* r = argv[5];
  char* rprime = argv[6];


//  NetIO * io = new NetIO(party==ALICE ? nullptr : "10.116.70.95", port);
//  NetIO * io = new NetIO(party==ALICE ? nullptr : "10.38.26.99", port); // Andrew
//  NetIO * io = new NetIO(party==ALICE ? nullptr : "192.168.0.153", port);
NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  Integer k_reconstruct[KEY_LENGTH];
  Integer p_reconstruct[DATA_LENGTH];
  Integer r_reconstruct[RANDOM_LENGTH];
  Integer rprime_reconstruct[RPRIME_LENGTH];

  for (int i = 0; i < KEY_LENGTH; i++) {
    k_reconstruct[i] = Integer(8, k_share[i], PUBLIC);
    //k_reconstruct[i] = Integer(8, '1', PUBLIC);
  }
  for (int i = 0; i < DATA_LENGTH; i++) {
    p_reconstruct[i] = Integer(8, p[i], PUBLIC);
  }
  for (int i = 0; i < RANDOM_LENGTH; i++) {
    r_reconstruct[i] = Integer(8, r[i], PUBLIC);
  }
  for (int i = 0; i < RPRIME_LENGTH; i++) {
    rprime_reconstruct[i] = Integer(8, r[i], PUBLIC);
  }

  // reconstructing everything between Alice and Bob 
  xor_reconstruct(k_share,k_share,KEY_LENGTH, k_reconstruct); 
  xor_reconstruct(p,p,DATA_LENGTH, p_reconstruct); 
  xor_reconstruct(r,r,RANDOM_LENGTH, r_reconstruct);
  xor_reconstruct(rprime,rprime,RPRIME_LENGTH, rprime_reconstruct);

  // parsing IDs from Data 
  Integer sn1[SN_LENGTH + 1];
  Integer sn2[SN_LENGTH + 1];
  Integer cid[32];
  Integer token[TOKEN_LENGTH];

  for (int i = 0; i < SN_LENGTH; i++) {
    sn1[i] = p_reconstruct[i];
    sn2[i] = p_reconstruct[i];
    //sn[i] = Integer(8,'1',PUBLIC);
  }
  sn1[SN_LENGTH] = Integer(8,'1',PUBLIC);
  sn2[SN_LENGTH] = Integer(8,'2',PUBLIC);
  // for (int i = SN_LENGTH; i < KEY_LENGTH; i++) {
  //  sn[i] = Integer(8,'0',PUBLIC);
  // }
  // sn[KEY_LENGTH-1] = Integer(8,'1', PUBLIC);

  for (int i = SN_LENGTH; i < DATA_LENGTH; i++) {
    cid[i - SN_LENGTH] = p_reconstruct[i];
  }
  for (int i = CID_LENGTH; i < 32; i++) {
    cid[i] = Integer(8,'\0',PUBLIC);
  }

  token[0] = Integer(8,'1',PUBLIC);

  Integer* label_key = runHmac(k_reconstruct,KEY_LENGTH,sn1,SN_LENGTH + 1);
  Integer* label = runHmac(label_key,KEY_LENGTH,token,TOKEN_LENGTH);
  cout << "PRINT LABEL OUTPUT" << endl;
  printIntegerArray(label,KEY_LENGTH,8);

  Integer utk[96];
  for (int i = 0; i < 32; i++) {
    utk[i] = label[i];
  }

  Integer* value_key = runHmac(k_reconstruct,KEY_LENGTH,sn2,SN_LENGTH + 1);
  Integer* hmac_key = runHmac(value_key,KEY_LENGTH,rprime_reconstruct,RPRIME_LENGTH);

  //xor padded cid with hmac_key 
  Integer ciphertext[32];
  for (int i = 0; i < 32; i++) {
    ciphertext[i] = hmac_key[i] ^ cid[i];
  }
  //xor_reconstruct(hmac_key,cid,32,ciphertext); 

  for (int i = 0; i < 32; i++) {
    utk[32 + i] = ciphertext[i];
  }
  for (int i = 0; i < 32; i++) {
    utk[64 + i] = rprime_reconstruct[i];
  }

  cout << "PRINT UTK ARRAY" << endl;
  printIntegerArray(utk,96,8);

  // shard it in half 
  Integer o1[96]; 
  // o2 is just r_reconstruct; 
  for (int i = 0; i < 96; i++) {
    o1[i] = utk[i] ^ r_reconstruct[i];
  }

  //revealing the output 

  cout << "reveal Alice output" << endl;
  for (int i = 0; i < 96; i++) {
    for (int j = 0; j < 8; j++) {
      cout << o1[i][j].reveal(ALICE);
    }
    cout << ", ";
  }
  cout << endl;

  cout << "reveal Bob output" << endl;
  for (int i = 0; i < 96; i++) {
    for (int j = 0; j < 8; j++) {
      cout << r_reconstruct[i][j].reveal(BOB);
    }
    cout << ", ";
  }
  delete io;  
  return 0;
}
