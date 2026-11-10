#include "emp-sh2pc/emp-sh2pc.h"
#include <memory>
#include <vector>
using namespace emp;
using namespace std;

// SH2PCSessionT<OTExt>: the same checks over each OT extension. Only BOB's
// private input bits use OT. With a 1024-OT refill batch, BOB's inputs below are
// served from the buffered batch (1 and 1000 bits), straddle a refill (100 bits)
// and exceed the batch (5000 bits, extended directly); every bit must come back
// unchanged. The 32-bit dot product then needs the OT labels and the garbling to
// share one Delta.
template <class OTExt>
static int run_case(IOChannel* io, int party, const char* name) {
	SH2PCSessionT<OTExt> sess(io, party, /*batch_sz=*/1024);
	int bad = 0;

	int offset = 0;
	for (int n : {1, 1000, 100, 5000}) {
		// A public bit pattern, so both parties can check BOB's bits.
		auto in = make_unique<bool[]>(n), out = make_unique<bool[]>(n);
		for (int i = 0; i < n; ++i) in[i] = ((unsigned)(offset + i) * 2654435761u >> 13) & 1;
		vector<block> w = sess.input_bits(BOB, in.get(), n);
		sess.reveal_bits(out.get(), PUBLIC, w.data(), n);
		for (int i = 0; i < n; ++i)
			if (out[i] != in[i]) {
				cout << name << ": BOB input bit " << offset + i << " changed" << endl;
				++bad;
				break;
			}
		offset += n;
	}

	using U32 = UInt_T<typename SH2PCSessionT<OTExt>::ctx_t, 32>;
	U32 acc = U32::constant(sess.ctx(), 0);
	uint32_t want = 0;
	for (uint32_t i = 0; i < 32; ++i) {
		uint32_t av = 0x9e3779b9u * (i + 1), bv = 0x85ebca6bu * (i + 7);
		U32 a = sess.template input<U32>(ALICE, av);
		U32 b = sess.template input<U32>(BOB, bv);
		acc = acc + a * b;
		want += av * bv;
	}
	uint32_t got = (uint32_t)sess.reveal(acc, PUBLIC).value();
	if (got != want) {
		cout << name << ": dot product " << got << ", want " << want << endl;
		++bad;
	}

	sess.finalize();
	cout << name << (bad ? ": FAIL" : ": ok") << endl;
	return bad;
}

int main(int argc, char** argv) {
	int party = parse_party(argv);
	int port = peer_port();
	auto io = (party == ALICE) ? NetIO::listen(port, /*quiet=*/true)
	                           : NetIO::connect(peer_ip(), port, /*quiet=*/true);
	int bad = 0;
	bad += run_case<IKNP>(io.get(), party, "IKNP");
	bad += run_case<SoftSpoken<4>>(io.get(), party, "SoftSpoken<4>");
	bad += run_case<Ferret>(io.get(), party, "Ferret");
	return bad == 0 ? 0 : 1;
}
