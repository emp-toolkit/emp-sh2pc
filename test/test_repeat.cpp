#include <unistd.h>
#include <memory>
#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;
using namespace std;

// Native SH2PCContext port: stand up and tear down a fresh session repeatedly,
// exercising the per-session handshake/lifecycle.

int party;
int port = 12345;

using SI = Int<SH2PCContext, 32>;

void test_int_reveal(int number) {
	usleep(100);
	NetIO netio(party == emp::ALICE ? nullptr : "127.0.0.1", port, true);
	SH2PCSession sess(&netio, party, 1024);
	SH2PCContext ctx(sess);

	SI a = sess.input<SI>(ctx, ALICE, (int64_t)number);
	SI b;
	for (int i = 0; i < 1000; ++i)
		b = sess.input<SI>(ctx, BOB, (int64_t)(number + 1));
	int32_t aa = (int32_t)sess.reveal(a, PUBLIC);
	int32_t bb = (int32_t)sess.reveal(b, PUBLIC);

	if (aa != number) error("int a!\n");
	if (bb != number + 1) error("int b!\n");
	sess.finalize();
}

int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	for (int i = 0; i < 100; ++i)
		test_int_reveal(1);
}
