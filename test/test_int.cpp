#include <typeinfo>
#include <cassert>
#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;
using namespace std;

// Native SH2PCContext port: UInt32 arithmetic over the value-return garbled
// backend. Each `runs` iteration is one full 32-bit op over the network; debug
// builds are ~100x slower, so cut to a smoke count there.
#ifdef NDEBUG
static constexpr int kRuns = 10000;
#else
static constexpr int kRuns = 100;
#endif

static block test_seed;

using U32 = UInt<SH2PCContext, 32>;

template <typename Op, typename Op2>
void test_int(SH2PCSession& sess, SH2PCContext& ctx, int runs = kRuns) {
	PRG prg(&test_seed);
	for (int i = 0; i < runs; ++i) {
		uint32_t ia, ib;
		prg.random_data_unaligned(&ia, 4);
		// Skip ib == 0 so divides / modulus don't hit native UB.
		do { prg.random_data_unaligned(&ib, 4); } while (ib == 0);

		U32 a = sess.input<U32>(ctx, ALICE, (uint64_t)ia);
		U32 b = sess.input<U32>(ctx, BOB,   (uint64_t)ib);
		U32 res = Op2()(a, b);

		uint32_t expected = Op()(ia, ib);
		uint32_t actual   = (uint32_t)sess.reveal(res, PUBLIC);
		if (actual != expected)
			cout << ia << "\t" << ib << "\t" << expected << "\t" << actual << endl << flush;
		assert(actual == expected);
	}
	cout << typeid(Op2).name() << "\t\t\tDONE" << endl;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);

	// Agree on the PRG seed for matched test inputs, before the session opens
	// so it isn't folded into the garbled-circuit transcript.
	if (party == ALICE) {
		PRG().random_block(&test_seed, 1);
		io.send_data(&test_seed, sizeof(block));
	} else {
		io.recv_data(&test_seed, sizeof(block));
	}
	io.flush();

	SH2PCSession sess(&io, party);
	SH2PCContext ctx(sess);

	test_int<std::plus<uint32_t>,       std::plus<U32>>(sess, ctx);
	test_int<std::minus<uint32_t>,      std::minus<U32>>(sess, ctx);
	test_int<std::multiplies<uint32_t>, std::multiplies<U32>>(sess, ctx);
	test_int<std::divides<uint32_t>,    std::divides<U32>>(sess, ctx);
	test_int<std::modulus<uint32_t>,    std::modulus<U32>>(sess, ctx);

	test_int<std::bit_and<uint32_t>,    std::bit_and<U32>>(sess, ctx);
	test_int<std::bit_or<uint32_t>,     std::bit_or<U32>>(sess, ctx);
	test_int<std::bit_xor<uint32_t>,    std::bit_xor<U32>>(sess, ctx);

	sess.finalize();
}
