#include "emp-sh2pc/emp-sh2pc.h"

template<typename T>
void test_millionare(int party, int number) {
	Integer<T> a(32, party == ALICE? number : 0, ALICE);
	Integer<T> b(32, party == BOB? number : 0, BOB);

	cout << "ALICE Input:\t"<<a.reveal()<<endl;
	cout << "BOB Input:\t"<<b.reveal()<<endl;
	cout << "ALICE larger?\t"<< (a>b).reveal()<<endl;
}

template<typename T>
void test_sort(int party) {
	int size = 10;
	Batcher batcher1, batcher2;
	Integer<T> *A = new Integer<T>[size];
	for(int i = 0; i < size; ++i) {
		batcher1.add<Integer<T>>(32, party == ALICE? rand()%1024 : 0);
		batcher2.add<Integer<T>>(32, party == BOB? rand()%1024 : 0 );
	}

	batcher1.make_semi_honest(ALICE);
	batcher2.make_semi_honest(BOB);

	for(int i = 0; i < size; ++i)
		A[i] = batcher1.next<Integer<T>>() ^ batcher2.next<Integer<T>>();

	sort(A, size);
	for(int i = 0; i < size; ++i)
		cout << A[i].reveal()<<endl;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

	setup_semi_honest(io, party);
//	test_millionare(party, atoi(argv[3]));
//	test_sort(party);
	delete io;
}
