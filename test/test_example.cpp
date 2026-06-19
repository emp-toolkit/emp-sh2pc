#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;
using namespace std;

// Millionaires' comparison over SH2PCSession: on signed 32-bit
// inputs, plus the running AND-gate count from the context.

using SI = Int_T<SH2PCSession::ctx_t, 32>;

void test_millionare(SH2PCSession& sess, int number) {
	SI a = sess.input<SI>(ALICE, (int64_t)number);
	SI b = sess.input<SI>(BOB,   (int64_t)number);
	Bit_T<SH2PCSession::ctx_t> res = a > b;

	cout << "ALICE larger?\t" << sess.reveal(res, PUBLIC).value() << endl;
}

int main(int argc, char** argv) {
	int port, party;
	party = parse_party(argv);
	port = peer_port();
	int num = 20;
	if (argc > 2) num = atoi(argv[2]);
	auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

	SH2PCSession sess(io.get(), party);
	test_millionare(sess, num);
	cout << sess.num_and() << endl;
	sess.finalize();
}
