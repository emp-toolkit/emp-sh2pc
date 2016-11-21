#include <typeinfo>
#include "semihonest/semihonest.h"
#include <emp-tool>

void test_float(int party) {
	Float a(24, 9, 0.11);
	Float b(24, 9, 0.41);
	cout << a.reveal<double>(PUBLIC)<<endl;
	cout << b.reveal<double>(PUBLIC)<<endl;
	cout << (a+b).reveal<double>(PUBLIC)<<endl;
	cout << (a-b).reveal<double>(PUBLIC)<<endl;
	cout << (a*b).reveal<double>(PUBLIC)<<endl;
	double res = (a/b).reveal<double>(BOB);
	cout << res <<endl;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr : SERVER_IP, port);

	setup_semi_honest(io, party);

	test_float(party);

	delete io;
	return 0;
}
