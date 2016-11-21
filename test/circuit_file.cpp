#include <emp-tool>
#include "semihonest/semihonest.h"
const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

//#define MEM
#define NETWORK
int main(int argc, char** argv) {
	int port, party;
	string file = circuit_file_location+"/AES-non-expanded.txt";//adder_32bit.txt";

	CircuitFile cf(file.c_str());

	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE?nullptr:SERVER_IP, port);

	setup_semi_honest(io, party);

#ifdef MEM
	Integer a(128, 2, ALICE);
	Integer b(128, 3, ALICE);
	Integer c(128, 1, PUBLIC);

	MemIO * memio = new MemIO(cf.table_size());
	if(party == ALICE)
		local_gc = new HalfGateGen<MemIO>(memio);
	else 
		local_gc = new HalfGateEva<MemIO>(memio);
	if(party == ALICE) {		
		double t1 = wallClock();
		for(int i = 0; i < 10000; ++i) {
			memio->clear();
			cf.compute((block*)c.bits, (block*)a.bits, (block*)b.bits);
		}
		cout << wallClock() - t1<< endl;
	}
#endif

#ifdef NETWORK
	io->set_nodelay();
	io->sync();
	double t1 = wallClock();
	Integer a(128, 2, ALICE);
	Integer b(128, 3, BOB);
	Integer c(128, 1, PUBLIC);
	for(int i = 0; i < 10000; ++i) {
			cf.compute((block*)c.bits, (block*)a.bits, (block*)b.bits);
	}
	cout << wallClock() - t1<<" "<<party<<" "<<c.reveal<string>(BOB)<<endl;
#endif
}
