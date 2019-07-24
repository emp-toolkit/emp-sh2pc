#ifndef SEMIHONEST_EVA_H__
#define SEMIHONEST_EVA_H__
#include <emp-tool/emp-tool.h>
#include <emp-ot/emp-ot.h>

namespace emp {
template<typename IO>
class SemiHonestEva: public ProtocolExecution {
public:
	IO* io = nullptr;
	SHOTExtension<IO>* ot;
	HalfGateEva<IO> * gc;
	PRG shared_prg;
	SemiHonestEva(IO *io, HalfGateEva<IO> * gc): ProtocolExecution(BOB) {
		this->io = io;
		ot = new SHOTExtension<IO>(io);
		this->gc = gc;	
		block seed; io->recv_block(&seed, 1);
		shared_prg.reseed(&seed);
	}
	~SemiHonestEva() {
		delete ot;
	}

	void feed(block * label, int party, const bool* b, int length) {
		if(party == ALICE) {
			shared_prg.random_block(label, length);
		} else {
			ot->recv_cot(label, b, length);
		}
	}

	void reveal(bool * b, int party, const block * label, int length) {
		if (party == XOR) {
			for (int i = 0; i < length; ++i) {
				if (isOne(&label[i]))
					b[i] = true;
				else if (isZero(&label[i]))
					b[i] = false;
				else 
					b[i] = getLSB(label[i]);
			}
			return;
		}
		for (int i = 0; i < length; ++i) {
			if(isOne(&label[i]))
				b[i] = true;
			else if (isZero(&label[i]))
				b[i] = false;
			else {
				bool lsb = getLSB(label[i]), tmp;
				if (party == BOB or party == PUBLIC) {
					io->recv_data(&tmp, 1);
					b[i] = (tmp != lsb);
				} else if (party == ALICE) {
					io->send_data(&lsb, 1);
					b[i] = false;
				}
			}
		}
		if(party == PUBLIC)
			io->send_data(b, length);
	}

};
}

#endif// GARBLE_CIRCUIT_SEMIHONEST_H__