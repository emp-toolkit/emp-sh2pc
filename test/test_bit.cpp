#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;
using namespace std;

// Native SH2PCContext port of the Bit smoke test: AND / XOR / NOT and the
// XOR-share reveal, over public / ALICE / BOB inputs.

NetIO* io;
int party;
static SH2PCSession* g_sess;
static SH2PCContext* g_ctx;

using B = Bit<SH2PCContext>;

static B mkbit(bool v, int owner) {
	if (owner == PUBLIC) return B::constant(*g_ctx, v);
	return g_sess->input<B>(*g_ctx, owner, v);
}

void test_bit() {
	bool b[] = {true, false};
	int p[] = {PUBLIC, ALICE, BOB};

	for (int i = 0; i < 2; ++i)
		for (int j = 0; j < 3; ++j)
			for (int k = 0; k < 2; ++k)
				for (int l = 0; l < 3; ++l) {
					{
						B b1 = mkbit(b[i], p[j]);
						B b2 = mkbit(b[k], p[l]);
						bool res = g_sess->reveal(b1 & b2, PUBLIC);
						if (res != (b[i] and b[k])) {
							cout << "AND" << i << " " << j << " " << k << " " << l << " " << res << endl;
							error("test bit error!");
						}
						res = g_sess->reveal(b1 & b1, PUBLIC);
						if (res != b[i]) { cout << "AND" << i << " " << j << res << endl; error("test bit error!"); }

						res = g_sess->reveal(b1 & (!b1), PUBLIC);
						if (res) { cout << "AND" << i << " " << j << res << endl; error("test bit error!"); }
					}
					{
						B b1 = mkbit(b[i], p[j]);
						B b2 = mkbit(b[k], p[l]);
						bool res = g_sess->reveal(b1 ^ b2, PUBLIC);
						if (res != (b[i] xor b[k])) {
							cout << "XOR" << i << " " << j << " " << k << " " << l << " " << res << endl;
							error("test bit error!");
						}
						res = g_sess->reveal(b1 ^ b1, PUBLIC);
						if (res) { cout << "XOR" << i << " " << j << res << endl; error("test bit error!"); }

						res = g_sess->reveal(b1 ^ (!b1), PUBLIC);
						if (!res) { cout << "XOR" << i << " " << j << res << endl; error("test bit error!"); }
					}
					{
						B b1 = mkbit(b[i], p[j]);
						B b2 = mkbit(b[k], p[l]);
						bool res = g_sess->reveal(b1 ^ b2, XOR);
						if (party == ALICE) {
							io->send_data(&res, 1);
						} else {
							bool tmp; io->recv_data(&tmp, 1);
							res = res != tmp;
							if (res != (b[i] xor b[k])) {
								cout << "XOR" << i << " " << j << " " << k << " " << l << " " << res << endl;
								error("test bit error!");
							}
						}
					}
				}
	io->flush();
	cout << "success!" << endl;
}

int main(int argc, char** argv) {
	int port;
	parse_party_and_port(argv, &party, &port);
	NetIO netio(party == ALICE ? nullptr : "127.0.0.1", port);
	io = &netio;
	SH2PCSession sess(io, party);
	SH2PCContext ctx(sess);
	g_sess = &sess;
	g_ctx = &ctx;
	test_bit();
	sess.finalize();
}
