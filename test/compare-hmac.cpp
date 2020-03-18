#include <emp-tool/emp-tool.h>
#include "emp-ag2pc/emp-ag2pc.h"
#include <openssl/hmac.h>

using namespace std;
using namespace emp;

bool compareHash(uint8_t* sslHash, Integer* empHash) {
  for (int i =0; i < 32; i++) {
    bitset<8> sslBitset(sslHash[i]);
    for (int j = 7; j >= 0; j--) {
      if(empHash[i][j].reveal() != sslBitset[j]) {
        return false;
      }
    }
    cout <<  sslBitset << ", ";
  }
  cout << endl << "TRUE?" << endl;
  return true;
}

void printHash(uint8_t* sslHash) {
  cout << "SSL hmac: ";
  for (int i =0; i < 32; i++) {
    bitset<8> sslBitset(sslHash[i]);
    cout <<  sslBitset << ", ";
  }
  cout << endl;
}

void printArray(bool* empHash) {
  cout << "EMP hmac: ";
  for(int i =0; i < 256; i ++) {
    cout << empHash[i];
  }
  cout << endl;
}

bool compareHash(uint8_t* sslHash, bool* empHash) {
  for (int i =0; i < 32; i++) {
    bitset<8> sslBitset(sslHash[i]);
    for (int j = 7; j >= 0; j--) {
      if(empHash[8*i-j] != sslBitset[j]) {
        return false;
      }
    }
    cout <<  sslBitset << ", ";
  }
  cout << endl << "TRUE!!" << endl;
  return true;
}

int main() {
    const char* message = (char*)"abcdefghabcdefghabcdefghabcdefgh";
    const char* key = (char*)"abcdefghabcdefghabcdefghabcdefgh";
    // bool mask[256];
    // bool maskedOutput[256];
    
    // const char* maskString = (char*)"1010001111100101100000000111010100101000110010000001100010010111101011100101000010110101001101101101011011110110000110111011110111111110110000010000110110011001010111010010010010010000100111011100001110001110001011010011000110111100101100010000100011101101";
    // for(int i = 0; i < 256; i ++) {
    //     mask[i] = maskString[i] == '1';
    // }
    // const char* maskedOutputString = (char*)"0001000101111101010011000000101110101111000110111000110011111001110011110100100011110100110110011010100001101001100101101100110101111101010000001001110100001000101100001000011110000011110010011101001100111110011101010100000011010001001001001111101110110000";
    // // for(int i = 0; i < 256; i ++) {
    // //     maskedOutput[i] = maskedOutputString[i] == '1';
    // // }
    // for(int i = 0; i < 32; i ++) {
    //   for(int j =0; j < 8; j ++) {
    //     maskedOutput[i*8+j] = maskedOutputString[i*8 + (7-j)] == '1';
    //   }
    // }
    uint8_t result[32];
    HMAC(EVP_sha256(), key, 32, (const unsigned char*)message, 32, result, NULL);

    bool unmaskedOutput[256];


    // for(int i = 0; i < 256; i ++) {
    //   unmaskedOutput[i] = mask[i] ^ maskedOutput[i];
    // }
    for(int i = 0; i < 32; i ++) {
      for(int j =0; j < 8; j ++) {
        unmaskedOutput[i*8+j] = mask[i*8 + (7-j)] ^ maskedOutput[i*8 + (7-j)];
      }
    }

    printArray(unmaskedOutput);
    printHash(result);
    compareHash(result, unmaskedOutput);
    cout << "Done" << endl; 
}
