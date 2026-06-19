#include <typeinfo>
#include <algorithm>
#include <iostream>
#include <cmath>
#include <cstring>
#include "emp-sh2pc/emp-sh2pc.h"

using namespace std;
using namespace emp;

// Float suite over SH2PCSession. Float32 arithmetic / comparison /
// classifier ops replay the fp32_*.empbc builtins through the value-return
// garbled backend; sign-bit ops (abs/neg/copysign) and select are local wiring.

#ifdef NDEBUG
static constexpr int kRuns = 1000;
#else
static constexpr int kRuns = 100;
#endif

using F   = Float_T<SH2PCSession::ctx_t, 32>;
using Bit = Bit_T<SH2PCSession::ctx_t>;

static F     finput(SH2PCSession& sess, int owner, float v) { return sess.input<F>(owner, v); }
static float frev(SH2PCSession& sess, const F& x)           { return sess.reveal(x, PUBLIC).value(); }
static bool  brev(SH2PCSession& sess, const Bit& b)         { return sess.reveal(b, PUBLIC).value(); }

// bit-exact: the on-disk circuits are correctly-rounded, so a passing op
// reproduces the host float bit-for-bit (incl. NaN/Inf patterns).
static bool exact(float got, float want) { return memcmp(&got, &want, sizeof(float)) == 0; }
static bool accurate(double a, double b, double err) {
	return fabs(a - b) < fabs(err * a) && fabs(a - b) < fabs(err * b);
}

template <typename Op, typename Op2>
int test_float(SH2PCSession& sess, PRG& prg, double precision, int runs = kRuns) {
	int bad = 0;
	for (int i = 0; i < runs; ++i) {
		int ia = 0, ib = 0;
		prg.random_data_unaligned(&ia, 4);
		prg.random_data_unaligned(&ib, 4);
		float da = (float)(ia) / 10000000.0;
		float db = (float)(ib) / 10000000.0;

		F a = finput(sess, ALICE, da);
		F b = finput(sess, BOB, db);
		F res = Op2()(a, b);
		float got = frev(sess, res), want = Op()(da, db);

		bool ok = precision > 0.0 ? accurate(got, want, precision) : exact(got, want);
		if (!ok) {
			cout << "Inaccuracy:\t" << typeid(Op2).name() << "\t" << da << "\t" << db
			     << "\t" << want << "\t" << got << endl << flush;
			++bad;
		}
	}
	cout << typeid(Op2).name() << "\t\t\tDONE  -  " << (bad ? "FAIL" : "ok") << endl;
	return bad;
}

static const char* unary_name[] = {"sqr", "sqrt", "recip", "rsqrt"};

int test_float_unary(SH2PCSession& sess, PRG& prg, int func_id, double precision,
                     double minimize, int runs = kRuns) {
	int bad = 0;
	for (int i = 0; i < runs; ++i) {
		long ia;
		prg.random_data_unaligned(&ia, sizeof(long));
		float da = ia / minimize;
		F a = finput(sess, ALICE, da);
		F res = a;
		float comp = 0.0f;
		switch (func_id) {
			case 0: res = a.sqr();          comp = da * da; break;
			case 1: res = a.abs().sqrt();   comp = std::sqrt(da > 0 ? da : -da); break;
			case 2: res = a.recip();        comp = 1.0f / da; break;
			case 3: res = a.abs().rsqrt();  comp = 1.0f / std::sqrt(da > 0 ? da : -da); break;
		}
		float got = frev(sess, res);
		bool ok = precision > 0.0 ? accurate(got, comp, precision) : exact(got, comp);
		if (!ok) {
			cout << "Inaccuracy:\t" << da << "\t\t" << comp << "\t" << got << endl << flush;
			++bad;
		}
	}
	cout << "function " << unary_name[func_id] << "\t\t\tDONE  -  accuracy : "
	     << (1.0 - (float)bad / runs) << endl;
	return bad;
}

// Comparison / select / abs / supported-op checks against the host result.
int fp_checks(SH2PCSession& sess) {
	int bad = 0;
	auto chk = [&](const char* label, double got, double want) {
		if (std::fabs(got - want) > 1e-9 * std::max(1.0, std::fabs(want))) {
			cout << label << " got " << got << " want " << want << endl; ++bad;
		}
	};
	auto chkb = [&](const char* label, bool got, bool want) {
		if (got != want) { cout << label << " got " << got << " want " << want << endl; ++bad; }
	};

	// comparison: equal pair and unequal pair.
	for (auto pr : {pair<float, float>{52.21875f, 52.21875f},
	                pair<float, float>{24.4332565f, 52.21875f}}) {
		float a = pr.first, b = pr.second;
		F x = finput(sess, ALICE, a), y = finput(sess, BOB, b);
		chkb("eq", brev(sess, x.equal(y)),      a == b);
		chkb("le", brev(sess, x.less_equal(y)), a <= b);
		chkb("lt", brev(sess, x.less_than(y)),  a < b);
	}

	// select: x.select(cond, other) == cond ? other : x.
	{
		float a = 24.4332565f, b = 52.21875f;
		F x = finput(sess, ALICE, a), y = finput(sess, BOB, b);
		Bit one  = Bit::constant(sess.ctx(), true);
		Bit zero = Bit::constant(sess.ctx(), false);
		chk("select true",  frev(sess, x.select(one, y)),  b);
		chk("select false", frev(sess, x.select(zero, y)), a);
	}

	// abs.
	{
		float a = -24.422432f;
		F x = finput(sess, ALICE, a);
		chk("abs", frev(sess, x.abs()), std::fabs(a));
	}

	// sign-bit / classifier ops on known inputs.
	{
		F a = finput(sess, ALICE, 2.0f), b = finput(sess, BOB, -3.0f);
		F c = finput(sess, PUBLIC, 4.0f), z = finput(sess, PUBLIC, 0.0f);
		chk("neg",      frev(sess, -a), -2.0);
		chk("copysign", frev(sess, a.copysign(b)), -2.0);
		chk("min",      frev(sess, a.min(b)), -3.0);
		chk("max",      frev(sess, a.max(b)), 2.0);
		chk("fma",      frev(sess, a.fma(b, c)), -2.0);
		chkb("ge",      brev(sess, a.greater_equal(b)), true);
		chkb("iszero",  brev(sess, z.is_zero()), true);
		chkb("isinf",   brev(sess, a.is_inf()), false);
		chkb("isnan",   brev(sess, a.is_nan()), false);
	}

	cout << "float checks (compare/select/abs/supported)\tDONE  -  " << (bad ? "FAIL" : "ok") << endl;
	return bad;
}

int main(int argc, char** argv) {
	int port, party;
	party = parse_party(argv);
	port = peer_port();
	auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

	// Agree on the PRG seed before the session opens so matched inputs are not
	// folded into the garbled-circuit transcript.
	block test_seed;
	if (party == ALICE) {
		PRG().random_block(&test_seed, 1);
		io->send_data(&test_seed, sizeof(block));
	} else {
		io->recv_data(&test_seed, sizeof(block));
	}
	io->flush();
	PRG prg(&test_seed);

	// Larger BOB-input COT batch keeps repeated float ops off the refill path.
	SH2PCSession sess(io.get(), party, 1024 * 1024);

	int fails = 0;
	fails += fp_checks(sess);
	fails += test_float<std::plus<float>,       std::plus<F>>(sess, prg, 0.0);
	fails += test_float<std::minus<float>,      std::minus<F>>(sess, prg, 0.0);
	fails += test_float<std::multiplies<float>, std::multiplies<F>>(sess, prg, 0.0);
	fails += test_float<std::divides<float>,    std::divides<F>>(sess, prg, 0.0);
	fails += test_float_unary(sess, prg, 0, 0.0, 1e12);
	fails += test_float_unary(sess, prg, 1, 0.0, 1e12);
	fails += test_float_unary(sess, prg, 2, 0.0, 1e12);
	fails += test_float_unary(sess, prg, 3, 0.0, 1e12);

	sess.finalize();
	if (party == BOB) cout << "test_float: " << (fails ? "FAILED" : "PASS") << endl;
	return fails ? 1 : 0;
}
