#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"

// Bind the circuit aliases to this backend wire (emp-tool sets no default).
EMP_USE_CIRCUIT_TYPES_ALL(block);
using namespace emp;
using namespace std;

// CI-time: each `runs` iteration is one full 32-bit garbled-circuit op
// over the network. Debug builds are ~100x slower, so cut to a smoke
// count there; Release keeps the full coverage.
#ifdef NDEBUG
static constexpr int kRuns = 10000;
#else
static constexpr int kRuns = 100;
#endif

// Shared test seed: ALICE samples it fresh per run, sends to BOB, so
// both sides draw the same (uint32_t, uint32_t) pairs without depending
// on a hard-coded public constant.
static block test_seed;

// UInt32 wraps mod 2^32 by spec, identical to native uint32_t — no
// range filtering or overflow-mismatch loop needed. Just sample full
// 32-bit inputs and compare.
template<typename Op, typename Op2>
void test_int(int party, int runs = kRuns) {
	PRG prg(&test_seed);
	for(int i = 0; i < runs; ++i) {
		uint32_t ia, ib;
		prg.random_data_unaligned(&ia, 4);
		// Skip ib == 0 so divides / modulus don't hit native UB.
		do {
			prg.random_data_unaligned(&ib, 4);
		} while (ib == 0);

		UInt32 a(ia, ALICE);
		UInt32 b(ib, BOB);

		UInt32 res = Op2()(a,b);

		uint32_t expected = Op()(ia, ib);
		uint32_t actual   = res.reveal<uint32_t>(PUBLIC);
		if (actual != expected) {
			cout << ia <<"\t"<<ib<<"\t"<<expected<<"\t"<<actual<<endl<<flush;
		}
		assert(actual == expected);
	}
	cout << typeid(Op2).name()<<"\t\t\tDONE"<<endl;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO io(party==ALICE ? nullptr : "127.0.0.1", port);

	// Agree on the PRG seed for matched test inputs: ALICE draws fresh
	// randomness and sends; BOB receives. Done before setup_semi_honest
	// so it doesn't get folded into the garbled-circuit transcript.
	if (party == ALICE) {
		PRG().random_block(&test_seed, 1);
		io.send_data(&test_seed, sizeof(block));
	} else {
		io.recv_data(&test_seed, sizeof(block));
	}
	io.flush();

	setup_semi_honest(&io, party);

	test_int<std::plus<uint32_t>,       std::plus<UInt32>>(party);
	test_int<std::minus<uint32_t>,      std::minus<UInt32>>(party);
	test_int<std::multiplies<uint32_t>, std::multiplies<UInt32>>(party);
	test_int<std::divides<uint32_t>,    std::divides<UInt32>>(party);
	test_int<std::modulus<uint32_t>,    std::modulus<UInt32>>(party);

	test_int<std::bit_and<uint32_t>,    std::bit_and<UInt32>>(party);
	test_int<std::bit_or<uint32_t>,     std::bit_or<UInt32>>(party);
	test_int<std::bit_xor<uint32_t>,    std::bit_xor<UInt32>>(party);

	finalize_semi_honest();
}
