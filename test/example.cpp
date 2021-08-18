#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;
using Integer = Integer_T<SemiHonestGarbledCircuit::wire_t>;
using Bit = Bit_T<SemiHonestGarbledCircuit::wire_t>;

void test_millionare(int party, int number) {
	Integer a(32, number, ALICE);
	Integer b(32, number, BOB);
	Bit res = a > b;

	cout << "ALICE larger?\t"<< res.reveal()<<endl;
}

void test_sort(int party) {
	int size = 100;
	Integer *A = new Integer[size];
	Integer *B = new Integer[size];
	Integer *res = new Integer[size];

// First specify Alice's input
	for(int i = 0; i < size; ++i)
		A[i] = Integer(32, rand()%102400, ALICE);


// Now specify Bob's input
	for(int i = 0; i < size; ++i)
		B[i] = Integer(32, rand()%102400, BOB);

//Now compute
	for(int i = 0; i < size; ++i)
		res[i] = A[i] ^ B[i];
	

	sort(res, size);
	for(int i = 0; i < 100; ++i)
		cout << res[i].reveal<int32_t>()<<endl;

	delete[] A;
	delete[] B;
	delete[] res;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	int num = 20;
	if(argc > 3)
		num = atoi(argv[3]);
	NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

	if(party == ALICE) emp::backend = new SemiHonestGen<NetIO>(io);
	else emp::backend = new SemiHonestEva<NetIO>(io);

	test_millionare(party, num);
//	test_sort(party);
	cout << emp::backend->num_and()<<endl;
	delete emp::backend;
	delete io;
}
