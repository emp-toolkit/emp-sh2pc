#include <cstring>
#include <vector>
#include <span>
#include "emp-sh2pc/emp-sh2pc.h"
#include "emp-tool/ir/builtins.h"   // builtin_circuit("aes128")

using namespace emp;
using namespace std;

// AES-128 over SH2PCSession: IR replay of aes128.empbc
// (256 inputs = plaintext(128) ‖ key(128) -> 128 ciphertext bits), driven
// through the value-return garbled backend. FIPS test vector for the all-zero
// plaintext/key.

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);

	SH2PCSession sess(&io, party);

	using Wire = SH2PCCtx::Wire;   // = block: the wire is the live garbled label
	bool zero[128];
	for (int i = 0; i < 128; ++i) zero[i] = false;
	std::vector<Wire> pt  = sess.input_bits(ALICE, zero, 128);  // plaintext = 0^128
	std::vector<Wire> key = sess.input_bits(BOB,   zero, 128);  // key       = 0^128

	std::vector<Wire> in(256);
	for (int i = 0; i < 128; ++i) { in[i] = pt[i]; in[128 + i] = key[i]; }
	std::vector<Wire> ct = execute_program(sess.ctx(), circuit::builtin_circuit("aes128"),
	                                       std::span<const Wire>(in.data(), 256));

	bool obits[128];
	sess.reveal_bits(obits, PUBLIC, ct.data(), 128);

	// AES-128(plaintext = 0^128, key = 0^128) FIPS vector; byte 0 first, LSB at
	// bit 0 within each byte — matches the recorded circuit's output ordering.
	static const uint8_t expected[16] = {
		0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
		0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
	};
	uint8_t actual[16];
	memset(actual, 0, 16);
	for (int i = 0; i < 128; ++i)
		if (obits[i]) actual[i / 8] |= (uint8_t)(1u << (i % 8));

	if (memcmp(actual, expected, 16) != 0)
		error("AES ciphertext mismatch");
	cout << "AES OK" << endl;
	cout << sess.num_and() << endl;

	sess.finalize();
}
