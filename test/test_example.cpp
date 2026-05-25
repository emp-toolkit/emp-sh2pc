#include "emp-sh2pc/emp-sh2pc.h"

// Bind the circuit aliases to this backend wire (emp-tool sets no default).
EMP_USE_CIRCUIT_TYPES_ALL(block);
using namespace emp;
using namespace std;

void test_millionare(int party, int number) {
	SignedInt a(32, number, ALICE);
	SignedInt b(32, number, BOB);
	Bit res = a > b;

	cout << "ALICE larger?\t"<< res.reveal<bool>()<<endl;
}

void test_sort(int party) {
	int size = 100;
	std::vector<SignedInt> A(size);
	std::vector<SignedInt> B(size);
	std::vector<SignedInt> res(size);

	for(int i = 0; i < size; ++i)
		A[i] = SignedInt(32, rand()%102400, ALICE);

	for(int i = 0; i < size; ++i)
		B[i] = SignedInt(32, rand()%102400, BOB);

	for(int i = 0; i < size; ++i)
		res[i] = A[i] ^ B[i];

	sort(res.data(), size);
	for(int i = 0; i < 100; ++i)
		cout << res[i].reveal<int32_t>()<<endl;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	int num = 20;
	if(argc > 3)
		num = atoi(argv[3]);
	NetIO io(party==ALICE ? nullptr : "127.0.0.1", port);

	setup_semi_honest(&io, party);
	test_millionare(party, num);
//	test_sort(party);
	cout << backend->num_and()<<endl;
	finalize_semi_honest();
}
