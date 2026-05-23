#include <cstring>
#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);
	setup_semi_honest(&io, party);

	// Cast the literal to __int128 so the (size_t, T, int) ctor copies
	// a full 16 bytes — passing a plain `0` (int) makes BitVec_T's
	// `bits_to_bools(tmp, &value, 128)` read 12 bytes of stack garbage
	// past the int, producing party-specific non-zero inputs that just
	// happen to be all-zero on some hosts.
	Integer plaintext(128, (__int128)0, ALICE);
	Integer key(128, (__int128)0, BOB);
	Integer ciphertext(128, (__int128)0, PUBLIC);

	AES_Calculator aes;
	aes.encrypt_with_key(plaintext.bits.data(),
	                     key.bits.data(),
	                     ciphertext.bits.data());

	// AES-128(plaintext = 0^128, key = 0^128) FIPS test vector.
	// Byte 0 first; LSB at bit 0 within each byte — matches
	// BitVec::reveal(void*) packing and AES_Calculator's buffer layout.
	static const uint8_t expected[16] = {
		0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
		0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
	};
	uint8_t actual[16];
	ciphertext.reveal(actual, PUBLIC);
	if (memcmp(actual, expected, 16) != 0)
		error("AES ciphertext mismatch");
	cout << "AES OK" << endl;
	cout << io.send_counter << endl;

	finalize_semi_honest();
}
