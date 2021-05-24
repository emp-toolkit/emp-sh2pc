#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;

int party;
int port = 12345;
NetIO * netio;
void setup() {
	usleep(100);
	netio =  new emp::NetIO(party == emp::ALICE ? nullptr : "127.0.0.1", port, true);
	emp::setup_semi_honest(netio, party,  1024);
}
void done() {
	delete netio;
	finalize_semi_honest();
}

void test_int_reveal(int number) {
	setup();
	Integer a(32, number, ALICE);
	Integer b;
	for(int i = 0; i < 1000; ++i)
		b = Integer(32, number+1, BOB);
	int32_t aa = a.reveal<int32_t>(PUBLIC);
	int32_t bb = b.reveal<int32_t>(PUBLIC);

	if(aa != number)error("int a!\n");
	if(bb != number+1) error("int b!\n");
	done();
}

int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	for(int i = 0; i < 100; ++i)
		test_int_reveal(1);
}
