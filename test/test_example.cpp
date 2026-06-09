#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;
using namespace std;

// Millionaires' comparison over SH2PCSession: on signed 32-bit
// inputs, plus the running AND-gate count from the context.

using SI = SH2PCSession::Int<32>;

void test_millionare(SH2PCSession& sess, int number) {
	SI a = sess.input<SI>(ALICE, (int64_t)number);
	SI b = sess.input<SI>(BOB,   (int64_t)number);
	SH2PCSession::Bit res = a > b;

	cout << "ALICE larger?\t" << sess.reveal(res, PUBLIC).value() << endl;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	int num = 20;
	if (argc > 3) num = atoi(argv[3]);
	NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);

	SH2PCSession sess(&io, party);
	test_millionare(sess, num);
	cout << sess.num_and() << endl;
	sess.finalize();
}
