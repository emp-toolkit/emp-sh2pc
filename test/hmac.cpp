// #include <openssl/hmac.h>
// #include <openssl/evp.h>
// #include "emp-sh2pc/emp-sh2pc.h"
// #include "sha-256.h"

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

