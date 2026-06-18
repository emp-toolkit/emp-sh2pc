#include <unistd.h>
#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;
using namespace std;

// SH2PCSession: stand up and tear down a fresh context repeatedly,
// exercising the per-context handshake/lifecycle.

using SI = Int_T<SH2PCSession::ctx_t, 32>;

static int test_int_reveal(int party, int port, int number) {
	// Brief pause so the previous iteration's listener has fully released the
	// port before this one re-binds it (same-port sequential reconnects).
	usleep(100);
	NetIO netio(party == ALICE ? nullptr : "127.0.0.1", port, true);
	SH2PCSession sess(&netio, party, 1024);

	SI a = sess.input<SI>(ALICE, (int64_t)number);
	SI b;
	for (int i = 0; i < 1000; ++i)
		b = sess.input<SI>(BOB, (int64_t)(number + 1));
	int32_t aa = (int32_t)sess.reveal(a, PUBLIC).value();
	int32_t bb = (int32_t)sess.reveal(b, PUBLIC).value();

	int bad = 0;
	if (aa != number)     { cout << "int a: got " << aa << " want " << number << endl; ++bad; }
	if (bb != number + 1) { cout << "int b: got " << bb << " want " << number + 1 << endl; ++bad; }
	sess.finalize();
	return bad;
}

int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);

	int fails = 0;
	for (int i = 0; i < 100; ++i)
		fails += test_int_reveal(party, port, 1);

	if (party == BOB) cout << "test_repeat: " << (fails ? "FAILED" : "PASS") << endl;
	return fails ? 1 : 0;
}
