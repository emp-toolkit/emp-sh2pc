#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;
using namespace std;

// Native SH2PCContext port: the millionaires' comparison on signed 32-bit
// inputs, plus the running AND-gate count from the session.

using SI = Int<SH2PCContext, 32>;

void test_millionare(SH2PCSession& sess, SH2PCContext& ctx, int number) {
	SI a = sess.input<SI>(ctx, ALICE, (int64_t)number);
	SI b = sess.input<SI>(ctx, BOB,   (int64_t)number);
	Bit<SH2PCContext> res = a > b;

	cout << "ALICE larger?\t" << sess.reveal(res, PUBLIC) << endl;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	int num = 20;
	if (argc > 3) num = atoi(argv[3]);
	NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);

	SH2PCSession sess(&io, party);
	SH2PCContext ctx(sess);
	test_millionare(sess, ctx, num);
	cout << sess.num_and() << endl;
	sess.finalize();
}
