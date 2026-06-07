#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;
using namespace std;

// Native SH2PCCtx port: the millionaires' comparison on signed 32-bit
// inputs, plus the running AND-gate count from the context.

using SI = Int_T<SH2PCCtx, 32>;

void test_millionare(SH2PCCtx& ctx, int number) {
	SI a = ctx.input<SI>(ALICE, (int64_t)number);
	SI b = ctx.input<SI>(BOB,   (int64_t)number);
	Bit_T<SH2PCCtx> res = a > b;

	cout << "ALICE larger?\t" << ctx.reveal(res, PUBLIC) << endl;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	int num = 20;
	if (argc > 3) num = atoi(argv[3]);
	NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);

	SH2PCCtx ctx(&io, party);
	test_millionare(ctx, num);
	cout << ctx.num_and() << endl;
	ctx.finalize();
}
