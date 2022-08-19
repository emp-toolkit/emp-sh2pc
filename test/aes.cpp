#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH)+string("bristol_format/");
const string circuit_file_location2 = macro_xstr(EMP_CIRCUIT_PATH)+string("bristol_fashion/");

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);
	setup_semi_honest(io, party);
	Integer a (128, 0, ALICE);
	Integer b (128, 0, BOB);
	Integer o (128, 0, PUBLIC);
	BristolFormat bf((circuit_file_location+"AES-non-expanded.txt").c_str());
	bf.compute(o.bits.data(), a.bits.data(), b.bits.data());
	cout << o.reveal<string>()<<endl;


	Integer a2 (256, 0, ALICE);
	Integer o2 (128, 0, PUBLIC);
	BristolFashion bf2((circuit_file_location2+"aes_128.txt").c_str());
	bf2.compute(o2.bits.data(), a2.bits.data());
	cout << o2.reveal<string>()<<endl;

	cout << io->counter<<endl;

	finalize_semi_honest();
	delete io;
}
