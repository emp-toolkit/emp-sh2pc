#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"

#include <algorithm>
#include <iostream>
#include <cmath>
#include <cstring>
#include <vector>
using namespace std;
using namespace emp;
using namespace emp::block_types;

vector<std::string> test_str{"sqr", "sqrt", "recip", "rsqrt"};

// CI-time: each `runs` iteration is one full 32-bit float circuit op
// over the network. Debug builds are ~100x slower, so cut to a smoke
// count there; Release keeps the full coverage.
#ifdef NDEBUG
static constexpr int kRuns = 1000;
#else
static constexpr int kRuns = 100;
#endif

void print_float32(Float a) {
	for(int i = 31; i >= 0; i--)
		printf("%d", a[i].reveal<bool>());
	cout << endl;
}

void print_float(float a) {
	unsigned char* c = (unsigned char*)&a;
	for(int i = 0; i < 4; i++)
		printf("%X", c[i]);
	cout << endl;
}

bool equal(Float a, float b) {
	unsigned char pa[sizeof(float)];
	memset(pa, 0, sizeof(float));
	unsigned char *pb = (unsigned char*)(&b);
	for(int i = 0; i < (int)sizeof(float); i++) {
		for(int j = 0; j < 8; j++) {
			pa[i] += (a[i*8+j].reveal<bool>())<<j;
		}
	}
	if(memcmp(pa, pb, sizeof(float)) == 0)
		return true;
	else return false; 
}

bool accurate(double a, double b, double err) {
	if (fabs(a - b) < fabs(err*a) and fabs(a - b) < fabs(err*b))
		return true;
	else return false;
}

// Shared test seed: ALICE samples it fresh per run, sends to BOB, so
// both sides draw the same float inputs without depending on a
// hard-coded public constant. Default-constructed here; reseeded after
// the io is open in main().
PRG prg;
template<typename Op, typename Op2>
bool test_float(double precision, int runs = kRuns) {
	int bad = 0;
	for(int i = 0; i < runs; ++i) {
		int ia = 0, ib = 0;
		prg.random_data_unaligned(&ia, 4);
		prg.random_data_unaligned(&ib, 4);
		float da = (float)(ia) / 10000000.0;
		float db = (float)(ib) / 10000000.0;

		Float a(da, ALICE);
		Float b(db, BOB);
		Float res = Op2()(a,b);
		
		if(precision > 0.0) {
			if (not accurate(res.reveal<double>(PUBLIC), Op()(da,db), precision)) {
				cout << "Inaccuracy:\t"<<typeid(Op2).name()<<"\t"<< da <<"\t"<<db<<"\t"<<Op()(da,db)<<"\n";
				cout << "\t\t\t"<<"\t"<< a.reveal<double>(PUBLIC) <<"\t"<<b.reveal<double>(PUBLIC)<<"\t"<<res.reveal<double>(PUBLIC)<<endl<<flush;
				++bad;
			}
		} else {
			if (not equal(res, Op()(da,db))) {
				cout << "Inaccuracy:\t"<<typeid(Op2).name()<<"\t"<< da <<"\t"<<db<<"\t"<<Op()(da,db)<<"\n";
				cout << "\t\t\t"<<"\t"<< a.reveal<double>(PUBLIC) <<"\t"<<b.reveal<double>(PUBLIC)<<"\t"<<res.reveal<double>(PUBLIC)<<endl<<flush;
				++bad;
			}
		}
	}
	cout << typeid(Op2).name()<<"\t\t\tDONE  -  "<<(bad ? "FAIL" : "ok")<<endl;
	return bad == 0;
}

bool test_float_unary(int func_id, double precision, double minimize, int runs = kRuns) {
	int rate_cnt = 0;
	for(int i = 0; i < runs; ++i) {
		long ia;
		prg.random_data_unaligned(&ia, sizeof(long));
		float da = ia / minimize;
		Float a(da, ALICE);
		Float res = Float(0.0, PUBLIC);
		float comp = 0.0;
		switch(func_id) {
			case 0: res = a.sqr();
				comp = da * da;
				break;
			case 1: res = a.abs().sqrt();
				comp = std::sqrt(da>0?da:(-da));
				break;
			case 2: res = a.recip();
				comp = 1.0f / da;
				break;
			case 3: res = a.abs().rsqrt();
				comp = 1.0f / std::sqrt(da>0?da:(-da));
				break;
		}
		if(precision == 0.0) {
			if (not equal(res, comp)) {
				cout << "Inaccuracy:\t"<<da<<"\t"<<"\t"<<comp<<"\t"<<res.reveal<double>(PUBLIC)<<endl<<flush;
				rate_cnt++;
			}
		} else {
			if (not accurate(res.reveal<double>(PUBLIC), comp, precision)) {
				cout << "Inaccuracy:\t"<<da<<"\t"<<"\t"<<comp<<"\t"<<res.reveal<double>(PUBLIC)<<endl<<flush;
				rate_cnt++;
			}
		}
	}
	cout << "function " << test_str[func_id] <<"\t\t\tDONE"<<"  -  accuracy : "<<(1.0-(float)rate_cnt/runs)<<endl;
	return rate_cnt == 0;
}

void scratch_pad(double num) {
	cout << "input: " << num << endl;
	Float x(num, PUBLIC);

	cout << "ultimate: ";
	for(int i = x.size()-1; i >= 0; i--) {
		cout << x.value[i].reveal<bool>(PUBLIC);
	}
	cout << endl;

	cout << "test reveal: ";
	cout << x.reveal<string>() << " or " << x.reveal<double>() << endl << endl;
}

void fp_cmp(double a, double b) {
	cout << "compare (eq, le, lt): " << a << " " << b << " - ";
	Float x(a, ALICE);
	Float y(b, BOB);

	Bit z = x.equal(y);
	cout << z.reveal<bool>() << " ";
	z = x.less_equal(y);
	cout << z.reveal<bool>() << " ";
	z = x.less_than(y);
	cout << z.reveal<bool>() << endl;
}

void fp_if(double a, double b) {
	cout << "if true/false: " << a << " " << b << " - ";
	Float x(a, ALICE);
	Float y(b, BOB);
	Bit one = Bit(true, PUBLIC);
	Bit zero = Bit(false, PUBLIC); 

	Float z = x.select(one, y);
	cout << z.reveal<string>() << " ";
	z = x.select(zero, y);
	cout << z.reveal<string>() << endl;
}

void fp_abs(double a) {
	cout << "abs: " << a << " - ";
	Float x(a, ALICE);

	Float z = x.abs();
	cout << z.reveal<string>() << endl;
}

bool fp_supported_smoke() {
	int bad = 0;
	auto chk = [&](const char* label, double got, double want) {
		if (std::fabs(got - want) > 1e-9 * std::max(1.0, std::fabs(want))) {
			cout << label << " got " << got << " want " << want << endl;
			++bad;
		}
	};
	auto chkb = [&](const char* label, bool got, bool want) {
		if (got != want) {
			cout << label << " got " << got << " want " << want << endl;
			++bad;
		}
	};

	Float a(2.0f, ALICE), b(-3.0f, BOB), c(4.0f, PUBLIC), z(0.0f, PUBLIC);
	chk("neg",      (-a).reveal<double>(PUBLIC), -2.0);
	chk("copysign", a.copysign(b).reveal<double>(PUBLIC), -2.0);
	chk("min",      a.min(b).reveal<double>(PUBLIC), -3.0);
	chk("max",      a.max(b).reveal<double>(PUBLIC), 2.0);
	chk("fma",      a.fma(b, c).reveal<double>(PUBLIC), -2.0);
	chkb("ge",      a.greater_equal(b).reveal<bool>(PUBLIC), true);
	chkb("iszero",  z.is_zero().reveal<bool>(PUBLIC), true);
	chkb("isinf",   a.is_inf().reveal<bool>(PUBLIC), false);
	chkb("isnan",   a.is_nan().reveal<bool>(PUBLIC), false);
	cout << "supported float smoke\t\tDONE  -  " << (bad ? "FAIL" : "ok") << endl;
	return bad == 0;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO io(party==ALICE ? nullptr : "127.0.0.1", port);

	// Agree on the PRG seed: ALICE draws fresh randomness and sends;
	// BOB receives. Done before setup_semi_honest so it doesn't get
	// folded into the garbled-circuit transcript.
	block test_seed;
	if (party == ALICE) {
		PRG().random_block(&test_seed, 1);
		io.send_data(&test_seed, sizeof(block));
	} else {
		io.recv_data(&test_seed, sizeof(block));
	}
	io.flush();
	prg.reseed(&test_seed);

	auto ctx = setup_semi_honest(&io, party);
	ctx->set_batch_size(1024*1024);//set larger BOB input processing batch size

	cout << "Test function:" << endl;
	fp_cmp(52.21875, 52.21875);
	fp_cmp(24.4332565, 52.21875);
	fp_if(24.4332565, 52.21875);
	fp_abs(-24.422432);
	fp_abs(24.422432);

	cout << endl << "Test accuracy:" << endl;
	bool ok = true;
	ok &= test_float<std::plus<float>, std::plus<Float>>(0.0);
	ok &= test_float<std::minus<float>, std::minus<Float>>(0.0);
	ok &= test_float<std::multiplies<float>, std::multiplies<Float>>(0.0);
	ok &= test_float<std::divides<float>, std::divides<Float>>(0.0);
	ok &= test_float_unary(0, 0.0, 1e12);
	ok &= test_float_unary(1, 0.0, 1e12);
	ok &= test_float_unary(2, 0.0, 1e12);
	ok &= test_float_unary(3, 0.0, 1e12);
	ok &= fp_supported_smoke();

	if (!ok)
		error("test_float failed");

	finalize_semi_honest();
	return 0;
}
