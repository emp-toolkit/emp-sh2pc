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

enum {
  SN_LENGTH = 12, CID_LENGTH = 4, DATA_LENGTH = 16, // data = sn + cid
  KEY_LENGTH = 32, RANDOM_LENGTH = 96, RPRIME_LENGTH = 32, TOKEN_LENGTH = 1
};
// static int SN_LENGTH = 12; 
// static int CID_LENGTH = 4;
// static int DATA_LENGTH = SN_LENGTH + CID_LENGTH;
// static int KEY_LENGTH = 32; 
// static int RANDOM_LENGTH = 96; 
// static int RPRIME_LENGTH = 32;
// static int TOKEN_LENGTH = 1;


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

void printarray(char* array, int ARRAY_LENGTH) {
    for (int i = 0; i <ARRAY_LENGTH; i ++) {
      for (int j = 0; j < 8; j++) {
        printf("%d", !!((array[i] << j) & 0x80));
      }
      printf(", ");
    }
  cout << endl;
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

Integer* convertStringtoIntegerArray(char* s, int S_LENGTH) {
  Integer output[S_LENGTH];
  for (int i =0; i < S_LENGTH; i++) {
    output[i] = Integer(8,s[i],PUBLIC);
  }
  //static Integer temp = output;
  static Integer* output_ptr = output; 
  return output_ptr;
}

bool compareUtk(char* expected, Integer* actual) {
  for (int i = 0; i < 96; i++) {
    for (int j = 0; j < 8; j++) {
      if ((int)!!((expected[i] << (7-j)) & 0x80) != (int)actual[i][j].reveal(PUBLIC)) {
        return false;
      }
    }
  }
  return true; 
}

char* find_utk(char* k_reconstruct, char* p_reconstruct, char* r_reconstruct, char* rprime_reconstruct) {

    char sn1[SN_LENGTH + 1];
    char sn2[SN_LENGTH + 1];
    char cid[32];
    char token[TOKEN_LENGTH]; 

    for (int i = 0; i < SN_LENGTH; i++) {
      sn1[i] = p_reconstruct[i];
      sn2[i] = p_reconstruct[i];
    //sn[i] = Integer(8,'1',PUBLIC);
    }
    sn1[SN_LENGTH] = '1';
    sn2[SN_LENGTH] = '2';
    for (int i = SN_LENGTH; i < DATA_LENGTH; i++) {
      cid[i - SN_LENGTH] = p_reconstruct[i];
    }
    for (int i = CID_LENGTH; i < 32; i++) {
      cid[i] = '\0';
    }
    token[0] = '1';
    uint8_t temp1[SHA256HashSize];
    HMAC(EVP_sha256(), k_reconstruct, KEY_LENGTH, (const unsigned char*)sn1, SN_LENGTH + 1, temp1, NULL);
    //printSSLHash(temp1, 32);
    char* label_key = (char*) temp1;
    uint8_t temp2[SHA256HashSize];
    HMAC(EVP_sha256(), label_key, KEY_LENGTH, (const unsigned char*)token, TOKEN_LENGTH, temp2, NULL);
    //cout << "printing label" << endl;
    //printSSLHash(temp2, 32);
    char* label = (char*) temp2;
    cout << "printing label from char" << endl; 
    //printarray(label,32);
    uint8_t temp3[SHA256HashSize];
    HMAC(EVP_sha256(), k_reconstruct, KEY_LENGTH, (const unsigned char*)sn2, SN_LENGTH + 1, temp3, NULL);
    //printSSLHash(temp3, 32);
    char* value_key = (char*) temp3;
    uint8_t temp4[SHA256HashSize];
    HMAC(EVP_sha256(), value_key, KEY_LENGTH, (const unsigned char*)rprime_reconstruct, RPRIME_LENGTH, temp4, NULL);
    //printSSLHash(temp4, 32);
    char* hmac_key = (char*) temp4;
    char ciphertext[32]; 
    for (int i = 0; i < 32; i++) {
      ciphertext[i] = (char)(hmac_key[i] ^ cid[i]); 
    }
    static char utk[96]; 
    for (int i = 0; i < 32; i++) {
      utk[i] = label[i];
    }
    for (int i = 0; i < 32; i++) {
      utk[32 + i] = ciphertext[i];
    }
    for (int i = 0; i < 32; i++) {
      utk[64 + i] = rprime_reconstruct[i];
    }

    char* output = utk;
    //printarray(output,96);
    //cout << "GETS HERE" << endl;
    return output;
}

Integer* find_secure_utk(Integer* k_reconstruct, Integer* p_reconstruct, Integer* r_reconstruct, Integer* rprime_reconstruct) {

  Integer sn1[SN_LENGTH + 1];
  Integer sn2[SN_LENGTH + 1];
  Integer cid[32];
  Integer token[TOKEN_LENGTH];

  for (int i = 0; i < SN_LENGTH; i++) {
    sn1[i] = p_reconstruct[i];
    sn2[i] = p_reconstruct[i];
  }
  sn1[SN_LENGTH] = Integer(8,'1',PUBLIC);
  sn2[SN_LENGTH] = Integer(8,'2',PUBLIC);

  for (int i = SN_LENGTH; i < DATA_LENGTH; i++) {
    cid[i - SN_LENGTH] = p_reconstruct[i];
  }
  for (int i = CID_LENGTH; i < 32; i++) {
    cid[i] = Integer(8,'\0',PUBLIC);
  }

  token[0] = Integer(8,'1',PUBLIC);

  Integer* label_key = runHmac(k_reconstruct,KEY_LENGTH,sn1,SN_LENGTH + 1);
  Integer* label = runHmac(label_key,KEY_LENGTH,token,TOKEN_LENGTH);
  //cout << "PRINT LABEL OUTPUT" << endl;
  //printIntegerArray(label,KEY_LENGTH,8);

  static Integer utk[96];
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

  for (int i = 0; i < 32; i++) {
    utk[32 + i] = ciphertext[i];
  }
  for (int i = 0; i < 32; i++) {
    utk[64 + i] = rprime_reconstruct[i];
  }

  // check if utk matches update-test 

  //cout << "PRINT UTK ARRAY" << endl;
  //printIntegerArray(utk,96,8);
  Integer* output = utk;
  return output;
}

void testUpdate1() {
  char* key = (char*)"NVxmjsCqBGkdRYd59AfCtaDCTMGqJ58B"; 
  char* data = (char*)"KKEyW9gWPnA7XvT3";
  char* random = (char*)"nXnqtkTMXn2dUnpjtxw6FAd57W2PUqzbKb87mu5hqYj8CWnkw7d2kEasP6fp8BC3Dgn28YBGdU3bMWpVACBc6TavzM8CZtVQ";
  char* rprimes = (char*)"WWmAfsr3ZKSA7u9JgSfcW3MGyfJEHEsq";
  //Integer* k = convertStringtoIntegerArray(key, KEY_LENGTH); 
  //Integer* p = convertStringtoIntegerArray(data, DATA_LENGTH); 
  //Integer* r = convertStringtoIntegerArray(random, RANDOM_LENGTH); 
  //Integer* rprime = convertStringtoIntegerArray(rprimes, RPRIME_LENGTH); 
  static Integer k[KEY_LENGTH];
  static Integer p[DATA_LENGTH]; 
  static Integer r[RANDOM_LENGTH];
  static Integer rprime[RPRIME_LENGTH];

  for (int i = 0; i < KEY_LENGTH; i++) {
    k[i] = Integer(8, key[i], PUBLIC);
  }
  for (int i = 0; i < DATA_LENGTH; i++) {
    p[i] = Integer(8, data[i], PUBLIC);
  }
  for (int i = 0; i < RANDOM_LENGTH; i++) {
    r[i] = Integer(8, random[i], PUBLIC);
  }
  for (int i = 0; i < RPRIME_LENGTH; i++) {
    rprime[i] = Integer(8, rprimes[i], PUBLIC);
  }

  char* utk1 = find_utk(key,data,random,rprimes);

  //cout << "gets to utk2" << endl;
  Integer* utk2 = find_secure_utk(k,p,r,rprime); 

  //cout << "printing utk1" << endl;
  //printarray(utk1,96);

  assert(compareUtk(utk1,utk2) == true);
}

void testUpdate2() {
  char* key = (char*)"dZ5uwfQBNHTTmWfLY6dje3BtYfgYnQca"; 
  char* data = (char*)"JtUJnhbF7wk7LRge";
  char* random = (char*)"X6skaVtAQMB8qBV7HV5pbh9f926WKKPd9aWwc9FAwrsV7ed8gsqwDpG7uVYp5pwrL7yDDfNyAJJmEfFaKC3AGLCACEZ4gYRw";
  char* rprimes = (char*)"JpVwaSp24MFRLdvReF3y7D5YRFsWXxdh";
  //Integer* k = convertStringtoIntegerArray(key, KEY_LENGTH); 
  //Integer* p = convertStringtoIntegerArray(data, DATA_LENGTH); 
  //Integer* r = convertStringtoIntegerArray(random, RANDOM_LENGTH); 
  //Integer* rprime = convertStringtoIntegerArray(rprimes, RPRIME_LENGTH); 
  static Integer k[KEY_LENGTH];
  static Integer p[DATA_LENGTH]; 
  static Integer r[RANDOM_LENGTH];
  static Integer rprime[RPRIME_LENGTH];

  for (int i = 0; i < KEY_LENGTH; i++) {
    k[i] = Integer(8, key[i], PUBLIC);
  }
  for (int i = 0; i < DATA_LENGTH; i++) {
    p[i] = Integer(8, data[i], PUBLIC);
  }
  for (int i = 0; i < RANDOM_LENGTH; i++) {
    r[i] = Integer(8, random[i], PUBLIC);
  }
  for (int i = 0; i < RPRIME_LENGTH; i++) {
    rprime[i] = Integer(8, rprimes[i], PUBLIC);
  }

  char* utk1 = find_utk(key,data,random,rprimes);

  //cout << "gets to utk2" << endl;
  Integer* utk2 = find_secure_utk(k,p,r,rprime); 

  //cout << "printing utk1" << endl;
  //printarray(utk1,96);

  assert(compareUtk(utk1,utk2) == true);
}

void convertHexToChar(char* hex, char* output, int output_length) {
  for (int i = 0; i < output_length; i++) {
    char c[2]; 
    c[0] = hex[2*i];
    c[1] = hex[2*i+1];
    int number = (int) strtol(c,NULL,16);
    output[i] = (char)number;
  }
}

int main(int argc, char** argv) {

  int port, party;
  parse_party_and_port(argv, &party, &port);

  char* k_share_hex = argv[3];
  char* p_hex = argv[4];
  char* r_hex = argv[5];
  char* rprime_hex = argv[6];
  //string hello = "1112131415161718";
  //char* test = (char*)hello.c_str();
  //unsigned char output[8];
  //printarray(test, 8); 
  //convertHexToChar(test,output,8); 



//  NetIO * io = new NetIO(party==ALICE ? nullptr : "10.116.70.95", port);
//  NetIO * io = new NetIO(party==ALICE ? nullptr : "10.38.26.99", port); // Andrew
//  NetIO * io = new NetIO(party==ALICE ? nullptr : "192.168.0.153", port);
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  //testUpdate1();  
  //testUpdate2();

  cout << "begin actual 2pc" << endl;
  char* k_share = k_share_hex;
  char* p = p_hex;
  char* r = r_hex;
  char* rprime = rprime_hex;
  convertHexToChar(k_share_hex,k_share,KEY_LENGTH);
  convertHexToChar(p_hex,p,DATA_LENGTH);
  convertHexToChar(r_hex,r,RANDOM_LENGTH);
  convertHexToChar(rprime_hex,rprime,RPRIME_LENGTH);

  static Integer k_reconstruct[KEY_LENGTH];
  static Integer p_reconstruct[DATA_LENGTH];
  static Integer r_reconstruct[RANDOM_LENGTH];
  static Integer rprime_reconstruct[RPRIME_LENGTH];

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

  Integer* k_reconstruct_ptr = k_reconstruct; 
  Integer* p_reconstruct_ptr = p_reconstruct; 
  Integer* r_reconstruct_ptr = r_reconstruct; 
  Integer* rprime_reconstruct_ptr = rprime_reconstruct; 

  // Calculate the token

  Integer* utk = find_secure_utk(k_reconstruct_ptr,p_reconstruct_ptr,r_reconstruct_ptr,rprime_reconstruct_ptr);

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
