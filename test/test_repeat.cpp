#include <unistd.h>
#include <memory>
#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;
using namespace std;

// Native SH2PCCtx port: stand up and tear down a fresh context repeatedly,
// exercising the per-context handshake/lifecycle.

int party;
int port = 12345;

using SI = Int_T<SH2PCCtx, 32>;

void test_int_reveal(int number) {
	usleep(100);
	NetIO netio(party == emp::ALICE ? nullptr : "127.0.0.1", port, true);
	SH2PCCtx ctx(&netio, party, 1024);

	SI a = ctx.input<SI>(ALICE, (int64_t)number);
	SI b;
	for (int i = 0; i < 1000; ++i)
		b = ctx.input<SI>(BOB, (int64_t)(number + 1));
	int32_t aa = (int32_t)ctx.reveal(a, PUBLIC);
	int32_t bb = (int32_t)ctx.reveal(b, PUBLIC);

	if (aa != number) error("int a!\n");
	if (bb != number + 1) error("int b!\n");
	ctx.finalize();
}

int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	for (int i = 0; i < 100; ++i)
		test_int_reveal(1);
}
