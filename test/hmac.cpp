/*
 *
 *
 */
#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
#include "tokens/tokens-misc.h"
#include "tokens/hmac.h"
#include "tokens/sha256.h"
using namespace emp;
using namespace std;

// crypto++ headers
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/hmac.h"
#include "cryptopp/sha.h"
#include "cryptopp/sha3.h"
#include "cryptopp/secblock.h"
#define byte unsigned char

// boost header to compare strings
#include <boost/algorithm/string.hpp>

string reference_HMAC_sign(CryptoPP::SecByteBlock key, string msg);
string run_secure_HMACsign(string key, string msg);
string test_output(Integer result[8]);

// this is not actually random because I don't seed rand().
// so it produces the same output every time it's compiled.
// would be cool to get something that the same for both parties, but different
// per compilation
// It's also not uniform because of our sketchy modding. #security
string gen_random(const int len) {
  static const char alphanum[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";

  string s = "";
  for (int i = 0; i < len; ++i) {
    s += alphanum[rand() % (sizeof(alphanum) - 1)];
  }
  return s;
}

/* openssl hard coded test generation

$ xxd /tmp/key
00000000: 766f 6e6a 7571 6662 6c6a 7475 6176 7461  vonjuqfbljtuavta
00000010: 6f6e 6c70 6678 6e66 767a 6c79 7671 6368  onlpfxnfvzlyvqch
00000020: 6d67 7369 6c72 6974 7578 736f 6667 7263  mgsilrituxsofgrc
00000030: 6663 7179 6e7a 756c 7a63 7375 746f 686d  fcqynzulzcsutohm

// SHORTER MESSAGE
$ xxd /tmp/msg 
00000000: 6463 6a62 7077 666d 7977 6f66 736c 6a79  dcjbpwfmywofsljy
00000010: 6175 637a 6d74 676c 6f77 7962 7464 6c63  auczmtglowybtdlc
00000020: 7865 6d61 7269 7a64 686d 6b7a 6a70 7a73  xemarizdhmkzjpzs
00000030: 6a76 747a 7969 6976 6871 7468 6776 706e  jvtzyiivhqthgvpn
00000040: 657a 6a67 6678 6466 6376 7075 7779 7466  ezjgfxdfcvpuwytf
00000050: 6d6c 7572 7773 6468 6964 686f 7364 616c  mlurwsdhidhosdal
00000060: 7469 6872 6277 7369 6e7a 7667 7376 7879  tihrbwsinzvgsvxy
00000070: 6864 6b7a                                hdkz

// LONGER MESSAGE
$ xxd /tmp/msg 
00000000: 6463 6a62 7077 666d 7977 6f66 736c 6a79  dcjbpwfmywofsljy
00000010: 6175 637a 6d74 676c 6f77 7962 7464 6c63  auczmtglowybtdlc
00000020: 7865 6d61 7269 7a64 686d 6b7a 6a70 7a73  xemarizdhmkzjpzs
00000030: 6a76 747a 7969 6976 6871 7468 6776 706e  jvtzyiivhqthgvpn
00000040: 657a 6a67 6678 6466 6376 7075 7779 7466  ezjgfxdfcvpuwytf
00000050: 6d6c 7572 7773 6468 6964 686f 7364 616c  mlurwsdhidhosdal
00000060: 7469 6872 6277 7369 6e7a 7667 7376 7879  tihrbwsinzvgsvxy
00000070: 6864 6b7a 7269 7a64 686d 6b7a 6a70 7a73  hdkzrizdhmkzjpzs
00000080: 6a76 747a 7969 6976 6871 7468 6776 706e  jvtzyiivhqthgvpn
00000090: 657a 6a67 6678 6466 6376 7075 7779 7466  ezjgfxdfcvpuwytf
000000a0: 6d6c 7572 7773 6468 6964 686f 7364 616c  mlurwsdhidhosdal
000000b0: 7469 6872 6c63 7865 6d61 7269 7a64 686d  tihrlcxemarizdhm

$ openssl dgst -sha256 -hmac $(cat /tmp/key) -hex /tmp/msg 
HMAC-SHA256(/tmp/msg)= af4e2daca29f7c6e68d6a0d536eec5a96527650a59506eea815062b782cc99bb
// LONGER MESSAGE OUTPUT
HMAC-SHA256(/tmp/msg)= fce631fb9384749b2c269b2390b9656080675782c0a14d828414029d07fe7930
*/

// The msgs we are signing are 116 bytes long, or 29 ints long
void test_end_to_end() {

  uint8_t test_key_bytes[64] = 
    { 0x76, 0x6f, 0x6e, 0x6a, 0x75, 0x71, 0x66, 0x62, 
      0x6c, 0x6a, 0x74, 0x75, 0x61, 0x76, 0x74, 0x61, 
      0x6f, 0x6e, 0x6c, 0x70, 0x66, 0x78, 0x6e, 0x66, 
      0x76, 0x7a, 0x6c, 0x79, 0x76, 0x71, 0x63, 0x68, 
      0x6d, 0x67, 0x73, 0x69, 0x6c, 0x72, 0x69, 0x74, 
      0x75, 0x78, 0x73, 0x6f, 0x66, 0x67, 0x72, 0x63, 
      0x66, 0x63, 0x71, 0x79, 0x6e, 0x7a, 0x75, 0x6c, 
      0x7a, 0x63, 0x73, 0x75, 0x74, 0x6f, 0x68, 0x6d };

  string test_key = "vonjuqfbljtuavtaonlpfxnfvzlyvqchmgsilrituxsofgrcfcqynzulzcsutohm";

  CryptoPP::SecByteBlock key(test_key_bytes, 64);

  // string msg = "dcjbpwfmywofsljyauczmtglowybtdlcxemarizdhmkzjpzsjvtzyiivhqthgvpnezjgfxdfcvpuwytfmlurwsdhidhosdaltihrbwsinzvgsvxyhdkz";
  string msg = "dcjbpwfmywofsljyauczmtglowybtdlcxemarizdhmkzjpzsjvtzyiivhqthgvpnezjgfxdfcvpuwytfmlurwsdhidhosdaltihrbwsinzvgsvxyhdkzrizdhmkzjpzsjvtzyiivhqthgvpnezjgfxdfcvpuwytfmlurwsdhidhosdaltihrlcxemarizdhm";
  
  string expected = reference_HMAC_sign(key, msg);
  string actual = run_secure_HMACsign(test_key, msg);

  boost::algorithm::to_lower(expected);
  boost::algorithm::to_lower(actual);

  assert ( expected.compare(actual) == 0);
  // assert ( expected.compare("af4e2daca29f7c6e68d6a0d536eec5a96527650a59506eea815062b782cc99bb") == 0 );
  assert ( expected.compare("fce631fb9384749b2c269b2390b9656080675782c0a14d828414029d07fe7930") == 0 );

  // randomized tests of 116 messages
  for (int i=0; i < 100; i++) {

    // TODO GENERATE RANDOM KEYS
    msg = gen_random(192);
    string expected = reference_HMAC_sign(key, msg);
    string actual = run_secure_HMACsign(test_key, msg);

    boost::algorithm::to_lower(expected);
    boost::algorithm::to_lower(actual);

    assert ( expected.compare(actual) == 0);

  }
  
  cout << "Passed 64 HMAC end-to-end tests." << endl;
}

// reference HMAC implementation by CryptoPP
string reference_HMAC_sign(CryptoPP::SecByteBlock key, string msg) {

  string mac;
  try {
      CryptoPP::HMAC< CryptoPP::SHA256 > hmac(key, key.size());

      CryptoPP::StringSource ss2(msg, true, 
          new CryptoPP::HashFilter(hmac,
              new CryptoPP::StringSink(mac)
          ) // HashFilter      
      ); // StringSource
  }
  catch(const CryptoPP::Exception& e)
  {
      cerr << e.what() << endl;
      exit(1);
  }
  
  string encoded;

  encoded.clear();
  CryptoPP::StringSource ss3(mac, true,
    new CryptoPP::HexEncoder(
        new CryptoPP::StringSink(encoded)
    ) // HexEncoder
  ); // StringSource

  return encoded;
}


// test hmac implementation 
string run_secure_HMACsign(string key, string msg) {

  string hex_key;

  CryptoPP::StringSource foo(key, true,
      new CryptoPP::HexEncoder (
        new CryptoPP::StringSink(hex_key)));

   string hex_msg;

  CryptoPP::StringSource bar(msg, true,
      new CryptoPP::HexEncoder (
        new CryptoPP::StringSink(hex_msg)));

  string temp;

  HMACKey_l merch_key_l;

  for(int i =0; i<16; i++) {
    temp = hex_key.substr(i*8, 8);
    merch_key_l.key[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  State_l state_l;

  for(int i=0; i<4; i++) {
    temp = hex_msg.substr(i*8, 8);
    state_l.nonce.nonce[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<8; i++) {
    temp = hex_msg.substr((i+4)*8, 8);
    state_l.rl.revlock[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<2; i++) {
    temp = hex_msg.substr((i+12)*8, 8);
    state_l.balance_cust.balance[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<2; i++) {
    temp = hex_msg.substr((i+14)*8, 8);
    state_l.balance_merch.balance[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<8; i++) {
    temp = hex_msg.substr((i+16)*8, 8);
    state_l.txid_merch.txid[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<8; i++) {
    temp = hex_msg.substr((i+24)*8, 8);
    state_l.txid_escrow.txid[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  } 

  for(int i=0; i<8; i++) {
    temp = hex_msg.substr((i+32)*8, 8);
    state_l.HashPrevOuts_merch.txid[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  }

  for(int i=0; i<8; i++) {
    temp = hex_msg.substr((i+40)*8, 8);
    state_l.HashPrevOuts_escrow.txid[i] = (uint32_t) strtoul(temp.c_str(), NULL, 16);
  } 

  // MPC - run hmac 
  PayToken_d paytoken_d;
  HMACKey_d merch_key_d = distribute_HMACKey(merch_key_l, MERCH);
  State_d state_d = distribute_State(state_l, CUST);
  HMACsign(merch_key_d, state_d, paytoken_d.paytoken);

  Integer hash = composeSHA256result(paytoken_d.paytoken);
  string res = hash.reveal_unsigned(PUBLIC,16);
  while (res.length() < 64) {
    res = '0' + res;
  }

  return res;
}

int main(int argc, char** argv) {
  // run in semihonest library
  int port, party;
  if (argc != 3) {
    cerr << "ERROR: not enough args" << endl;
    return 1;
  }
  parse_party_and_port(argv, &party, &port);
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  // run end-to-end tests
  test_end_to_end();

  delete io;
  return 0;
}
