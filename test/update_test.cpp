#include <emp-tool/emp-tool.h>
#include "emp-tool/utils/hash.h"
#include "emp-sh2pc/emp-sh2pc.h"
#include "sha.h"
#include "sha-private.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <ctype.h>

using namespace emp;
using namespace std;
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

void printarray(char* array, int ARRAY_LENGTH) {
  	for (int i = 0; i <ARRAY_LENGTH; i ++) {
  		for (int j = 0; j < 8; j++) {
  			printf("%d", !!((array[i] << j) & 0x80));
  		}
  		printf(", ");
  	}
	cout << endl;
}

int main(int argc, char** argv) {
	static int SN_LENGTH = 12; 
  	static int CID_LENGTH = 4;
  	static int DATA_LENGTH = SN_LENGTH + CID_LENGTH;
  	static int KEY_LENGTH = 32; 
  	static int RANDOM_LENGTH = 96; 
  	static int RPRIME_LENGTH = 32;
  	static int TOKEN_LENGTH = 1;

  	char* k_share1 = argv[1];
  	char* k_share2 = argv[2];
  	char* p1 = argv[3];
  	char* p2 = argv[4];
  	char* r1 = argv[5];
  	char* r2 = argv[6];
  	char* rprime1 = argv[7];
  	char* rprime2 = argv[8];

  	char k_reconstruct[KEY_LENGTH];
  	char p_reconstruct[DATA_LENGTH];
  	char r_reconstruct[RANDOM_LENGTH];
  	char rprime_reconstruct[RPRIME_LENGTH];

  	for (int i = 0; i < KEY_LENGTH; i++) {
    	k_reconstruct[i] = (char)(k_share1[i] ^ k_share2[i]);
    //k_reconstruct[i] = Integer(8, '1', PUBLIC);
  	}
  	for (int i = 0; i < DATA_LENGTH; i++) {
    	p_reconstruct[i] = (char)(p1[i] ^ p2[i]);
  	}
  	for (int i = 0; i < RANDOM_LENGTH; i++) {
    	r_reconstruct[i] = (char)(r1[i] ^ r2[i]);
  	}
  	for (int i = 0; i < RPRIME_LENGTH; i++) {
    	rprime_reconstruct[i] = (char)(rprime1[i] ^ rprime2[i]);
  	}
  	//printarray(k_reconstruct,KEY_LENGTH); 
  	//printarray(p_reconstruct,DATA_LENGTH); 
  	//printarray(r_reconstruct,RANDOM_LENGTH); 
  	//printarray(rprime_reconstruct,RPRIME_LENGTH); 

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
  	cout << "printing label" << endl;
  	printSSLHash(temp2, 32);
  	char* label = (char*) temp2;

  	cout << "printing label from char" << endl; 
  	printarray(label,32);

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


  	char utk[96]; 
  	for (int i = 0; i < 32; i++) {
    	utk[i] = label[i];
  	}
  	for (int i = 0; i < 32; i++) {
    	utk[32 + i] = ciphertext[i];
  	}
  	for (int i = 0; i < 32; i++) {
   		utk[64 + i] = rprime_reconstruct[i];
  	}

  	cout << "PRINT UTK ARRAY" << endl;
  	printarray(utk,96);

  	char o1[96]; 
  	for (int i = 0; i < 96; i ++) {
  		o1[i] = (char)(utk[i] ^ r_reconstruct[i]); 
  	}

  	cout << "reveal ALICE output" << endl; 
  	for (int i = 0; i <96; i ++) {
  		for (int j = 7; j > -1; j--) {
  			printf("%d", !!((o1[i] << j) & 0x80));
  		}
  		printf(", ");
  	}
  	cout << endl;

  	cout << "reveal BOB output" << endl; 
  	for (int i = 0; i <96; i ++) {
  		for (int j = 7; j > -1; j--) {
  			printf("%d", !!((r_reconstruct[i] << j) & 0x80));
  		}
  		printf(", ");
  	}
  	cout << endl;


  	return 0;

}