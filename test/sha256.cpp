/*
 * This runs end-to-end tests on the sha256 functionality
 * and unit tests on the individual components
 * (in build_tokens/sha256.*)
 *
 * Unit tests verify that the component funtions produce the same output
 * on normal integers and secret Integers.
 *
 * End-to-end tests are run on vectors from Briston (TODO: add link)
 * and on vectors generated at random. Currently not using a seeded rand function (TODO)
 * The reference implementation is CryptoPP.
 * Padding is always executed in the clear; padding implementation is from some guy on stackoverflow
 *
 */
#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
#include "sha256.h"
using namespace emp;
using namespace std;

// crypto++ headers
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/sha.h"
#include "cryptopp/sha3.h"
#define byte unsigned char

// boost header to compare strings
#include <boost/algorithm/string.hpp>

enum Version { INSEC2, SEC1, SEC2, SEC3 };


/* implementation of SHA256 from FIPS PUB 180-4 
 * with the following modifications
 * - processes only a fixed length input (BLOCKS)
 * - assumes padding already exists
 */

Integer ROR32(Integer x, Integer n) {
  Integer thirtytwo(BITS, 32, PUBLIC);
  return (x >> n) | (x << (thirtytwo - n));
}
Integer ROR32(Integer x, uint n) {
  int shiftamt = 32 - n;
  return (x >> n) | (x << shiftamt);
}
uint ROR32(uint x, uint n) {
  return ((x >> n) | (x << (32 - n)));
}


void initSHA256(Integer k[64], Integer H[8]) {
  for(int i=0; i<64; i++) {
    k[i] = Integer(BITS, k_clear[i], PUBLIC);
  }
  for(int i=0; i<8; i++) {
    H[i] = Integer(BITS, IV_clear[i], PUBLIC);
  }
}

string get_bitstring(Integer x) {
  string s = "";
  for(int i=0; i<x.size(); i++) {
    s = (x[i].reveal<bool>(PUBLIC) ? "1" : "0") + s;
  }
  return s;
}

// result is 8 32-bit integers
// hash   is 1 256-bit integer
// hash = result[0] || result[1] || ... || result[7]
Integer composeSHA256result(Integer result[8]) {
  Integer thirtytwo(256, 32, PUBLIC);
  result[0].resize(256, false);
  Integer hash = result[0];
  for(int i=1; i<8; i++) {
    result[i].resize(256, false);
    hash = (hash << thirtytwo) | result[i];
  }
  return hash;
}

void computeInnerHashBlock( Integer k[64], Integer H[8], Integer w[64]) {
  Integer a,b,c,d,e,f,g,h;
  // prepare message schedule

  // 1. Prepare the message schedule, {Wt} (0-15 initialized from message)
  for(size_t t = 16 ; t <= 63 ; t++) {
    w[t] = SIGMA_LOWER_1(w[t-2]) + w[t-7] + SIGMA_LOWER_0(w[t-15]) + w[t-16];
  }

  // 2. Initialize working variables
  a = H[0];
  b = H[1];
  c = H[2];
  d = H[3];
  e = H[4];
  f = H[5];
  g = H[6];
  h = H[7];

  // 3. Compress: update working variables
  for (int t=0; t < 64; t++) {
    Integer temp1 = h + SIGMA_UPPER_1(e) + CH(e, f, g) + k[t] + w[t];
    Integer temp2 = SIGMA_UPPER_0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  // 4. Set new hash values
  H[0] = H[0] + a;
  H[1] = H[1] + b;
  H[2] = H[2] + c;
  H[3] = H[3] + d;
  H[4] = H[4] + e;
  H[5] = H[5] + f;
  H[6] = H[6] + g;
  H[7] = H[7] + h;
}

/* computes sha256 for a 2-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 */
void computeSHA256_2l(uint message[2][16], Integer result[8]) {
  // initialize constants and initial hash digest value
  const int BLOCKS = 2;
  Integer k[64];
  Integer H[8];
  Integer w[BLOCKS][64];
  // initialize message schedule
  for (int i=0; i<BLOCKS; i++) {
    for(size_t t=0; t<16; t++) {
      // todo: figure out who the message belongs to
      w[i][t] = Integer(BITS, message[i][t], CUST);
    }
  }

  initSHA256(k, H);

  for (int i=0; i<BLOCKS; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}


/* computes sha256 for 1-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 */
void computeSHA256_1d(Integer message[1][16], Integer result[8]) {

  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[64];
  // initialize message schedule
  for(size_t t=0; t<16; t++) {
    w[t] = message[0][t];
  }

  initSHA256(k, H);
  computeInnerHashBlock(k, H, w);

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}


/* computes sha256 for a 2-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 */
void computeSHA256_2d(Integer message[2][16], Integer result[8]) {
  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[2][64];
  // initialize message schedule
  for (int i=0; i<2; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<2; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}


/* computes sha256 for 3-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 */
void computeSHA256_3d(Integer message[3][16], Integer result[8]) {

  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[3][64];
  // initialize message schedule
  for (int i=0; i<3; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<3; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}

void computeSHA256_4d(Integer message[4][16], Integer result[8]) {
  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[4][64];
  // initialize message schedule
  for (int i=0; i<4; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<4; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}

void computeSHA256_5d(Integer message[5][16], Integer result[8]) {
  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[5][64];
  // initialize message schedule
  for (int i=0; i<5; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<5; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}



void computeDoubleSHA256_3d(Integer message[3][16], Integer result[8]) {

  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[3][64];
  // initialize message schedule
  for (int i=0; i<3; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<3; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  // for(int i=0; i<8; i++) {
  //   result[i] = H[i];
  // }

  // make a new buffer for the itterated hash

  Integer newmessage[1][16];

  for(int i=0; i<8; i++) {
    newmessage[0][i] = H[i];
  }

  newmessage[0][8] = Integer(32, 2147483648/*0x80000000*/, PUBLIC);
  for(int i=9; i<15; i++) {
    newmessage[0][i] = Integer(32, 0/*0x00000000*/, PUBLIC);
  }
  newmessage[0][15] = Integer(32, 256, PUBLIC);

  computeSHA256_1d(newmessage, result);
}


void computeDoubleSHA256_4d(Integer message[4][16], Integer result[8]) {

  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[4][64];
  // initialize message schedule
  for (int i=0; i<4; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<4; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  // make a new buffer for the itterated hash

  Integer newmessage[1][16];

  for(int i=0; i<8; i++) {
    newmessage[0][i] = H[i];
  }

  newmessage[0][8] = Integer(32, 2147483648/*0x80000000*/, PUBLIC);
  for(int i=9; i<15; i++) {
    newmessage[0][i] = Integer(32, 0/*0x00000000*/, PUBLIC);
  }
  newmessage[0][15] = Integer(32, 256, PUBLIC);

  computeSHA256_1d(newmessage, result);
}

void computeDoubleSHA256_5d(Integer message[5][16], Integer result[8]) {

  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[5][64];
  // initialize message schedule
  for (int i=0; i<5; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<5; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  // make a new buffer for the itterated hash

  Integer newmessage[1][16];

  for(int i=0; i<8; i++) {
    newmessage[0][i] = H[i];
  }

  newmessage[0][8] = Integer(32, 2147483648/*0x80000000*/, PUBLIC);
  for(int i=9; i<15; i++) {
    newmessage[0][i] = Integer(32, 0/*0x00000000*/, PUBLIC);
  }
  newmessage[0][15] = Integer(32, 256, PUBLIC);

  computeSHA256_1d(newmessage, result);
}



string SHA256HashString(string msg);
string run_secure_sha256(string msg, uint blocks, Version test_type);
string test_output(Integer result[8]);

void test_sigmas(int party, int range=1<<25, int runs=50) {
  PRG prg;
  for(int i = 0; i < runs; ++i) {
    unsigned long long x;
    prg.random_data(&x, 8);
    x %= range;
    Integer a(BITS,  x, ALICE);

    // make sure both parties have same clear values
    x = a.reveal<uint>(PUBLIC);

    // test sigma functions
    uint result = SIGMA_UPPER_0(a).reveal<uint>(PUBLIC);
    assert ((SIGMA_UPPER_0(x)) == result);

    result = SIGMA_UPPER_1(a).reveal<uint>(PUBLIC);
    assert ((SIGMA_UPPER_1(x)) == result);

    result = SIGMA_LOWER_0(a).reveal<uint>(PUBLIC);
    assert ((SIGMA_LOWER_0(x)) == result);

    result = SIGMA_LOWER_1(a).reveal<uint>(PUBLIC);
    assert ((SIGMA_LOWER_1(x)) == result);
  }

  cout << "Passed " << runs << " tests of SHA256 basic sigma functions." << endl;
}

void test_components(int party, int range=1<<25, int runs=50) {
  PRG prg;
  for(int i = 0; i < runs; ++i) {
    unsigned long long x,y,z, n;
    prg.random_data(&x, 8);
    prg.random_data(&y, 8);
    prg.random_data(&z, 8);
    prg.random_data(&n, 8);
    x %= range;
    y %= range;
    z %= range;
    n %= 32;

    Integer a(BITS,  x, ALICE);
    Integer b(BITS,  y, ALICE);
    Integer c(BITS,  z, BOB);
    Integer pn(BITS, n, BOB);

    // make sure both parties have same clear values
    x = a.reveal<uint>(PUBLIC);
    y = b.reveal<uint>(PUBLIC);
    z = c.reveal<uint>(PUBLIC);
    n = pn.reveal<uint>(PUBLIC);

    // test ch
    uint result = CH(a,b,c).reveal<uint>(PUBLIC);
    assert ((CH(x,y,z)) == result);

    // test maj
    result = MAJ(a,b,c).reveal<uint>(PUBLIC);
    assert ((MAJ(x,y,z)) == result);

    // test shr32
    result = SHR32(a, pn).reveal<uint>(PUBLIC);
    assert ((SHR32(x, n)) == result);

    // test rot32
    result = ROR32(a, pn).reveal<uint>(PUBLIC);
    assert (ROR32(x,n) == result);
  }
  cout << "Passed " << runs << " tests of SHA256 component functions." << endl;
}

// tests compose function (takes 8-block result, squashes into long hash)
// (comparison is to the in-the-clear version I've been using)
// TODO This is broken
void test_compose(int runs=50) {
  // reveal result, parse final hash
  PRG prg;
  unsigned long long range = 1;
  range = range << 32; // doing this in one line raises too-short error

  for(int i = 0; i < runs; ++i) {
    Integer result[8];
    unsigned long long rs[8];
    for(int r=0; r<8; r++) {
      prg.random_data(&(rs[r]), 8);
      rs[r] %= range;
    }
    // this segfaults when I try to initilize results in the loop
    result[0] = Integer(32, (uint) rs[0], ALICE);
    result[1] = Integer(32, (uint) rs[1], BOB);
    result[2] = Integer(32, (uint) rs[2], BOB);
    result[3] = Integer(32, (uint) rs[3], ALICE);
    result[4] = Integer(32, (uint) rs[4], BOB);
    result[5] = Integer(32, (uint) rs[5], ALICE);
    result[6] = Integer(32, (uint) rs[6], BOB);
    result[7] = Integer(32, (uint) rs[7], ALICE);

    // in the clear
    string res = "";
    for (int r=0; r<8; r++){
      res += get_bitstring(result[r]);
    }
    res = change_base(res, 2, 16);

    // secure -- note use of special unsigned reveal function
    Integer hash = composeSHA256result(result);
    string hres = change_base(hash.reveal_unsigned(PUBLIC), 10,16);

    assert ( hres.compare(res) == 0 );
  }
  cout << "Passed " << runs << " tests for SHA256 output formatting" << endl;
}


// this is not actually random because I don't seed rand().
// so it produces the same output every time it's compiled.
// would be cool to get something that the same for both parties, but different
// per compilation
// It's also not uniform because of our sketchy modding.
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

void test_known_vector2() {
  // known test vector from di-mgt.com.au
  string msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  string expected = SHA256HashString(msg);
  string actual = run_secure_sha256(msg, 2, INSEC2);

  boost::algorithm::to_lower(expected);
  boost::algorithm::to_lower(actual);

  cout << actual << endl;
  assert ( expected.compare(actual) == 0);
  assert ( expected.compare("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0 );
}


void test_end_to_end() {
  // randomized tests of 1-3 block-length messages
  for (int len=0; len < 184; len++) {
    string msg = gen_random(len);
    string expected = SHA256HashString(msg);
    string actual;

    if (len < 56) {
      actual = run_secure_sha256(msg, 1, SEC1);
    } else if (len < 120) {
      actual = run_secure_sha256(msg, 2, SEC2);
      string insec_actual = run_secure_sha256(msg, 2, INSEC2);
      assert (actual.compare(insec_actual) == 0);
    } else { // len < 184
      actual = run_secure_sha256(msg, 3, SEC3);
    }

    boost::algorithm::to_lower(expected);
    boost::algorithm::to_lower(actual);

    assert ( expected.compare(actual) == 0);
  }
  
  cout << "Passed 248 SHA256 end-to-end tests." << endl;
}

// reference sha256 implementation by CryptoPP
string SHA256HashString(string msg){
  string digest;
  CryptoPP::SHA256 hash;

  CryptoPP::StringSource foo(msg, true,
      new CryptoPP::HashFilter(hash,
        new CryptoPP::HexEncoder (
          new CryptoPP::StringSink(digest))));

  return digest;
}

// Pad the input to a multiple of 512 bits, and add the length
// in binary to the end.
// This was implemented by Jerry Coffin from StackExchange
string padSHA256(string const &input) {
  static const size_t block_bits = 512;
  uint64_t length = input.size() * 8 + 1;
  size_t remainder = length % block_bits;
  size_t k = (remainder <= 448) ? 448 - remainder : 960 - remainder;
  std::string padding("\x80");
  padding.append(std::string(k/8, '\0'));
  --length;

  for (int i=sizeof(length)-1; i>-1; i--) {
    unsigned char bc = length >> (i*8) & 0xff;
    padding.push_back(bc);
  }
  std::string ret(input+padding);
  return ret;
}

// test sha256 implementation 
string run_secure_sha256(string msg, uint blocks, Version test_type) {
  uint msg_blocks[blocks][16];
  memset( msg_blocks, 0, blocks*16*sizeof(uint) );

  // pad message using insecure scheme
  string padded_msg = padSHA256(msg);
  string padded_msg_hex;

  // encode message in hex using cryptopp tools
  CryptoPP::StringSource foo(padded_msg, true,
      new CryptoPP::HexEncoder (
        new CryptoPP::StringSink(padded_msg_hex)));

  // parse padded message into blocks
  assert (padded_msg_hex.length() == blocks * 128);
  string blk;
  for (uint b=0; b<blocks; b++) {
    for (int i=0; i<16; i++) {
      blk = padded_msg_hex.substr((b*128) + (i*8), 8);
      msg_blocks[b][i] = (uint) strtoul(blk.c_str(), NULL,16);
    }
  }
  Integer result[8];

  // MPC - run sha256 for different block lengths
  if (test_type == INSEC2) {
    computeSHA256_2l(msg_blocks, result);
  } else { // SEC1 || SEC2 || SEC3
    Integer sec_blocks[blocks][16];
    for (uint b=0; b < blocks; b++) {
      for (int t=0; t < 16; t++) {
        sec_blocks[b][t] = Integer(BITS, msg_blocks[b][t], CUST);
      }
    }
    
    switch (test_type) {
      case SEC1 : computeSHA256_1d(sec_blocks, result); break;
      case SEC2 : computeSHA256_2d(sec_blocks, result); break;
      case SEC3 : computeSHA256_3d(sec_blocks, result); break;
      default : cout << "impossible! not implemented" << endl;
    }
  }

  // convert output to correct-length string
  Integer hash = composeSHA256result(result);
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
  NetIO * io = new NetIO(party==ALICE ? nullptr : "10.38.26.99", port);

  setup_semi_honest(io, party);

    // setup_plain_prot(true, "sha256.circuit.txt");

  // // run unit tests
  // test_components(party);
  // test_sigmas(party);
  // test_compose();

  // // run end-to-end tests
  // test_end_to_end();  
  // string msg = "abcdbcdecdefdefgefghfghighijhijk";
  // string actual = run_secure_sha256(msg, 1, SEC1);


  test_known_vector2();
// finalize_plain_prot();  

  delete io;
  return 0;
}
