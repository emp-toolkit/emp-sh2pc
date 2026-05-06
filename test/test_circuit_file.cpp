#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;
const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

int port, party;
string file = circuit_file_location+"/bristol_format/AES-non-expanded.txt";//adder_32bit.txt";
BristolFormat cf(file.c_str());

void test() {
	auto start = clock_start();
	// 128-bit width but `int`-typed value — cast to __int128 so the
	// BitVec_T ctor's bits_to_bools(&value, 128 bits) reads a full
	// 16 zero-extended bytes instead of 12 bytes of stack garbage.
	Integer a(128, (__int128)2, ALICE);
	Integer b(128, (__int128)3, BOB);
	Integer c(128, (__int128)1, PUBLIC);
	for(int i = 0; i < 10000; ++i) {
			cf.compute(c.bits.data(), a.bits.data(), b.bits.data());
	}
	cout << time_from(start)<<" "<<party<<" "<<c.reveal<string>(BOB)<<endl;

}
int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	NetIO io(party==ALICE?nullptr:"127.0.0.1", port);

	setup_semi_honest(&io, party);
	test();

	finalize_semi_honest();
}
