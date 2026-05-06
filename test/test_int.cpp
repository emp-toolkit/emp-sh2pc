#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;

template<typename Op, typename Op2>
void test_int(int party, int range1 = 1<<20, int range2 = 1<<20, int runs = 10000) {
	PRG prg(fix_key);
	for(int i = 0; i < runs; ++i) {
		long long ia, ib;
		prg.random_data_unaligned(&ia, 8);
		prg.random_data_unaligned(&ib, 8);
		ia %= range1;
		ib %= range2;
		while( Op()(int(ia), int(ib)) != Op()(ia, ib) ) {
			prg.random_data_unaligned(&ia, 8);
			prg.random_data_unaligned(&ib, 8);
			ia %= range1;
			ib %= range2;
		}
	
		Integer a(32, ia, ALICE); 
		Integer b(32, ib, BOB);

		Integer res = Op2()(a,b);

		if (res.reveal<int>(PUBLIC) != Op()(ia,ib)) {
			cout << ia <<"\t"<<ib<<"\t"<<Op()(ia,ib)<<"\t"<<res.reveal<int>(PUBLIC)<<endl<<flush;
		}
		assert(res.reveal<int>(PUBLIC) == Op()(ia,ib));
	}
	cout << typeid(Op2).name()<<"\t\t\tDONE"<<endl;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO io(party==ALICE ? nullptr : "127.0.0.1", port);

	setup_semi_honest(&io, party);

	test_int<std::plus<int>, std::plus<Integer>>(party);
	test_int<std::minus<int>, std::minus<Integer>>(party);
	test_int<std::multiplies<int>, std::multiplies<Integer>>(party);
	test_int<std::divides<int>, std::divides<Integer>>(party);
	test_int<std::modulus<int>, std::modulus<Integer>>(party);

	test_int<std::bit_and<int>, std::bit_and<Integer>>(party);
	test_int<std::bit_or<int>, std::bit_or<Integer>>(party);
	test_int<std::bit_xor<int>, std::bit_xor<Integer>>(party);

	finalize_semi_honest();
}
