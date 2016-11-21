#include "semihonest.h"
#include <emp-tool>

void test_bit(int party) {
	bool b[] = {true, false};
	int p[] = {PUBLIC, ALICE, BOB};

	for(int i = 0; i < 2; ++i)
		for(int j = 0; j < 3; ++j)
			for(int k = 0; k < 2; ++k)
				for (int l= 0; l < 3; ++l)  {
					{
						Bit b1(b[i], p[j]);
						Bit b2(b[k], p[l]);
						bool res = (b1&b2).reveal(BOB);
						if(party == BOB) {
							if(res != (b[i] and b[k]))
								cout<<"AND" <<i<<" "<<j<<" "<<k<<" "<<l<<" "<<res<<endl;
							assert(res == (b[i] and b[k]));
						}
					}
					{
						Bit b1(b[i], p[j]);
						Bit b2(b[k], p[l]);
						bool res = (b1^b2).reveal(BOB);
						if(party == BOB) {
							if(res != (b[i] xor b[k]))
								cout <<"XOR"<<i<<" "<<j<<" "<<k<<" "<<l<< " " <<res<<endl;
							assert(res == (b[i] xor b[k]));
						}
					}
				}
	cout <<"success!"<<endl;
}

int main(int argc, char** argv) {
	int port, party;
	parse_party_and_port(argv, &party, &port);
	NetIO * io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);
	setup_semi_honest(io, party);
	test_bit(party);
	delete io;
}
