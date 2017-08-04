#include "emp-sh2pc/emp-sh2pc.h"
const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

int port, party;
string file = circuit_file_location+"/AES-non-expanded.txt";//adder_32bit.txt";
CircuitFile cf(file.c_str());

template<typename T>
void test() {
	auto start = clock_start();
	Integer<T> a(128, 2, ALICE);
	Integer<T> b(128, 3, BOB);
	Integer<T> c(128, 1, PUBLIC);
	for(int i = 0; i < 10000; ++i) {
			cf.compute<T>((block*)c.bits, (block*)a.bits, (block*)b.bits);
	}
	cout << time_from(start)<<" "<<party<<" "<<c.reveal(BOB)<<endl;

}
int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);

	setup_semi_honest(io, party);
	if (party == ALICE)
		test<HalfGateGen<NetIO>>();
	else
		test<HalfGateEva<NetIO>>();
	
	delete io;
}
