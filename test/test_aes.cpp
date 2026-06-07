#include <cstring>
#include <vector>
#include <span>
#include "emp-sh2pc/emp-sh2pc.h"
#include "emp-tool/circuits/builtin_circuit_files.h"   // builtin_circuit("aes128")

using namespace emp;
using namespace std;

// Native SH2PCCtx port: AES-128 as IR replay of aes128.empbc
// (256 inputs = plaintext(128) ‖ key(128) -> 128 ciphertext bits), driven
// through the value-return garbled backend. FIPS test vector for the all-zero
// plaintext/key.

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);

	SH2PCCtx ctx(&io, party);

	bool zero[128];
	for (int i = 0; i < 128; ++i) zero[i] = false;
	std::vector<SHWire> pt  = ctx.input_bits(ALICE, zero, 128);  // plaintext = 0^128
	std::vector<SHWire> key = ctx.input_bits(BOB,   zero, 128);  // key       = 0^128

	std::vector<SHWire> in(256);
	for (int i = 0; i < 128; ++i) { in[i] = pt[i]; in[128 + i] = key[i]; }
	std::vector<SHWire> ct = execute_program(ctx, circuit::builtin_circuit("aes128"),
	                                         std::span<const SHWire>(in.data(), 256));

	bool obits[128];
	ctx.reveal_bits(obits, PUBLIC, ct.data(), 128);

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
	cout << ctx.num_and() << endl;

	ctx.finalize();
}
