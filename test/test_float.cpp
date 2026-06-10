#include <typeinfo>
#include <algorithm>
#include <iostream>
#include <cmath>
#include <cstring>
#include <vector>
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

using F = Float_T<SH2PCSession::DirectCtx, 32>;

static SH2PCSession* g_ctx;

static F finput(int owner, float v) { return g_ctx->input<F>(owner, v); }
static float frev(const F& x) { return g_ctx->reveal(x, PUBLIC).value(); }
static bool brev(const Bit_T<SH2PCSession::DirectCtx>& b) { return g_ctx->reveal(b, PUBLIC).value(); }

// bit-exact: the on-disk circuits are correctly-rounded, so a passing op
// reproduces the host float bit-for-bit (incl. NaN/Inf patterns).
static bool exact(float got, float want) { return memcmp(&got, &want, sizeof(float)) == 0; }
static bool accurate(double a, double b, double err) {
	return fabs(a - b) < fabs(err * a) && fabs(a - b) < fabs(err * b);
}

PRG prg;

template <typename Op, typename Op2>
bool test_float(double precision, int runs = kRuns) {
	int bad = 0;
	for (int i = 0; i < runs; ++i) {
		int ia = 0, ib = 0;
		prg.random_data_unaligned(&ia, 4);
		prg.random_data_unaligned(&ib, 4);
		float da = (float)(ia) / 10000000.0;
		float db = (float)(ib) / 10000000.0;

		F a = finput(ALICE, da);
		F b = finput(BOB, db);
		F res = Op2()(a, b);
		float got = frev(res), want = Op()(da, db);

		bool ok = precision > 0.0 ? accurate(got, want, precision) : exact(got, want);
		if (!ok) {
			cout << "Inaccuracy:\t" << typeid(Op2).name() << "\t" << da << "\t" << db
			     << "\t" << want << "\t" << got << endl << flush;
			++bad;
		}
	}
	cout << typeid(Op2).name() << "\t\t\tDONE  -  " << (bad ? "FAIL" : "ok") << endl;
	return bad == 0;
}

static const char* unary_name[] = {"sqr", "sqrt", "recip", "rsqrt"};

bool test_float_unary(int func_id, double precision, double minimize, int runs = kRuns) {
	int rate_cnt = 0;
	for (int i = 0; i < runs; ++i) {
		long ia;
		prg.random_data_unaligned(&ia, sizeof(long));
		float da = ia / minimize;
		F a = finput(ALICE, da);
		F res = finput(PUBLIC, 0.0f);
		float comp = 0.0f;
		switch (func_id) {
			case 0: res = a.sqr();          comp = da * da; break;
			case 1: res = a.abs().sqrt();   comp = std::sqrt(da > 0 ? da : -da); break;
			case 2: res = a.recip();        comp = 1.0f / da; break;
			case 3: res = a.abs().rsqrt();  comp = 1.0f / std::sqrt(da > 0 ? da : -da); break;
		}
		float got = frev(res);
		bool ok = precision > 0.0 ? accurate(got, comp, precision) : exact(got, comp);
		if (!ok) {
			cout << "Inaccuracy:\t" << da << "\t\t" << comp << "\t" << got << endl << flush;
			rate_cnt++;
		}
	}
	cout << "function " << unary_name[func_id] << "\t\t\tDONE  -  accuracy : "
	     << (1.0 - (float)rate_cnt / runs) << endl;
	return rate_cnt == 0;
}

void fp_cmp(double a, double b) {
	cout << "compare (eq, le, lt): " << a << " " << b << " - ";
	F x = finput(ALICE, (float)a), y = finput(BOB, (float)b);
	cout << brev(x.equal(y)) << " " << brev(x.less_equal(y)) << " " << brev(x.less_than(y)) << endl;
}

void fp_if(double a, double b) {
	cout << "if true/false: " << a << " " << b << " - ";
	F x = finput(ALICE, (float)a), y = finput(BOB, (float)b);
	Bit_T<SH2PCSession::DirectCtx> one = Bit_T<SH2PCSession::DirectCtx>::constant(g_ctx->direct_ctx(), true);
	Bit_T<SH2PCSession::DirectCtx> zero = Bit_T<SH2PCSession::DirectCtx>::constant(g_ctx->direct_ctx(), false);
	cout << frev(x.select(one, y)) << " " << frev(x.select(zero, y)) << endl;
}

void fp_abs(double a) {
	cout << "abs: " << a << " - ";
	F x = finput(ALICE, (float)a);
	cout << frev(x.abs()) << endl;
}

bool fp_supported_smoke() {
	int bad = 0;
	auto chk = [&](const char* label, double got, double want) {
		if (std::fabs(got - want) > 1e-9 * std::max(1.0, std::fabs(want))) {
			cout << label << " got " << got << " want " << want << endl; ++bad;
		}
	};
	auto chkb = [&](const char* label, bool got, bool want) {
		if (got != want) { cout << label << " got " << got << " want " << want << endl; ++bad; }
	};

	F a = finput(ALICE, 2.0f), b = finput(BOB, -3.0f);
	F c = finput(PUBLIC, 4.0f), z = finput(PUBLIC, 0.0f);
	chk("neg",      frev(-a), -2.0);
	chk("copysign", frev(a.copysign(b)), -2.0);
	chk("min",      frev(a.min(b)), -3.0);
	chk("max",      frev(a.max(b)), 2.0);
	chk("fma",      frev(a.fma(b, c)), -2.0);
	chkb("ge",      brev(a.greater_equal(b)), true);
	chkb("iszero",  brev(z.is_zero()), true);
	chkb("isinf",   brev(a.is_inf()), false);
	chkb("isnan",   brev(a.is_nan()), false);
	cout << "supported float smoke\t\tDONE  -  " << (bad ? "FAIL" : "ok") << endl;
	return bad == 0;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);

	// Agree on the PRG seed before the session opens.
	block test_seed;
	if (party == ALICE) {
		PRG().random_block(&test_seed, 1);
		io.send_data(&test_seed, sizeof(block));
	} else {
		io.recv_data(&test_seed, sizeof(block));
	}
	io.flush();
	prg.reseed(&test_seed);

	// Larger BOB-input COT batch keeps repeated float ops off the refill path.
	SH2PCSession sess(&io, party, 1024 * 1024);
	g_ctx = &sess;

	cout << "Test function:" << endl;
	fp_cmp(52.21875, 52.21875);
	fp_cmp(24.4332565, 52.21875);
	fp_if(24.4332565, 52.21875);
	fp_abs(-24.422432);
	fp_abs(24.422432);

	cout << endl << "Test accuracy:" << endl;
	bool ok = true;
	ok &= test_float<std::plus<float>, std::plus<F>>(0.0);
	ok &= test_float<std::minus<float>, std::minus<F>>(0.0);
	ok &= test_float<std::multiplies<float>, std::multiplies<F>>(0.0);
	ok &= test_float<std::divides<float>, std::divides<F>>(0.0);
	ok &= test_float_unary(0, 0.0, 1e12);
	ok &= test_float_unary(1, 0.0, 1e12);
	ok &= test_float_unary(2, 0.0, 1e12);
	ok &= test_float_unary(3, 0.0, 1e12);
	ok &= fp_supported_smoke();

	if (!ok) error("test_float failed");

	sess.finalize();
	return 0;
}
