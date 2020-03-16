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

int main(int argc, char** argv) {
  // run in semihonest library
  int port, party;
  parse_party_and_port(argv, &party, &port);

  char* inputVal = argv[3];
  int inputLength = atoi(argv[4]);
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  // xor secret sharing 

  
  Integer intMsg[inputLength];
  for (int i = 0; i < inputLength; i++) {
    intMsg[i] = Integer(8, inputVal[i], ALICE);
  }

  Integer r1[inputLength]; 
  for (int i = 0; i < inputLength; i++) {
  	r1[i] = Integer(8, )
  }

  delete io;
  return 0;
}