#include "emp-sh2pc/emp-sh2pc.h"

using namespace emp;
using namespace std;

// Bit smoke test over SH2PCSession: AND / XOR / NOT and the
// XOR-share reveal, over public / ALICE / BOB inputs.

using B = Bit_T<SH2PCSession::ctx_t>;

static B mkbit(SH2PCSession& sess, bool v, int owner) {
	if (owner == PUBLIC) return B::constant(sess.ctx(), v);
	return sess.input<B>(owner, v);
}

static int test_bit(SH2PCSession& sess, NetIO& io, int party) {
	bool b[] = {true, false};
	int p[] = {PUBLIC, ALICE, BOB};
	int bad = 0;

	for (int i = 0; i < 2; ++i)
		for (int j = 0; j < 3; ++j)
			for (int k = 0; k < 2; ++k)
				for (int l = 0; l < 3; ++l) {
					{
						B b1 = mkbit(sess, b[i], p[j]);
						B b2 = mkbit(sess, b[k], p[l]);
						bool res = sess.reveal(b1 & b2, PUBLIC).value();
						if (res != (b[i] and b[k])) {
							cout << "AND " << i << " " << j << " " << k << " " << l << " " << res << endl; ++bad;
						}
						if (sess.reveal(b1 & b1, PUBLIC).value() != b[i]) {
							cout << "AND-self " << i << " " << j << endl; ++bad;
						}
						if (sess.reveal(b1 & (!b1), PUBLIC).value()) {
							cout << "AND-not " << i << " " << j << endl; ++bad;
						}
					}
					{
						B b1 = mkbit(sess, b[i], p[j]);
						B b2 = mkbit(sess, b[k], p[l]);
						bool res = sess.reveal(b1 ^ b2, PUBLIC).value();
						if (res != (b[i] xor b[k])) {
							cout << "XOR " << i << " " << j << " " << k << " " << l << " " << res << endl; ++bad;
						}
						if (sess.reveal(b1 ^ b1, PUBLIC).value()) {
							cout << "XOR-self " << i << " " << j << endl; ++bad;
						}
						if (!sess.reveal(b1 ^ (!b1), PUBLIC).value()) {
							cout << "XOR-not " << i << " " << j << endl; ++bad;
						}
					}
					{
						// XOR-share reveal: each party gets a share; reconstruct and
						// check on BOB.
						B b1 = mkbit(sess, b[i], p[j]);
						B b2 = mkbit(sess, b[k], p[l]);
						bool res = sess.reveal(b1 ^ b2, XOR).value();
						if (party == ALICE) {
							io.send_data(&res, 1);
						} else {
							bool tmp; io.recv_data(&tmp, 1);
							res = res != tmp;
							if (res != (b[i] xor b[k])) {
								cout << "XOR-share " << i << " " << j << " " << k << " " << l << " " << res << endl; ++bad;
							}
						}
					}
				}
	io.flush();
	return bad;
}

int main(int argc, char** argv) {
	int port, party;
	party = parse_party(argv);
	port = peer_port();
	auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);
	SH2PCSession sess(io.get(), party);

	int fails = test_bit(sess, *io, party);

	sess.finalize();
	if (party == BOB) cout << "test_bit: " << (fails ? "FAILED" : "PASS") << endl;
	return fails ? 1 : 0;
}
