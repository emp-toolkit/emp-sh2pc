#ifndef EMP_SEMIHONEST_GEN_H__
#define EMP_SEMIHONEST_GEN_H__
#include "emp-sh2pc/sh_party.h"

namespace emp {

template<typename IO>
class SemiHonestGen: public SemiHonestParty<IO> { public:
	HalfGateGen<IO> * gc;
	SemiHonestGen(IO* io, HalfGateGen<IO>* gc): SemiHonestParty<IO>(io, ALICE) {
		this->gc = gc;
		bool delta_bool[128];
		block_to_bool(delta_bool, gc->delta);
		this->ot->setup_send(delta_bool);
		block seed;
		PRG prg;
		prg.random_block(&seed, 1);
		this->io->send_block(&seed, 1);
		this->shared_prg.reseed(&seed);
		refill();
	}

	void refill() {
		this->ot->send_cot(this->buf, this->batch_size);
		this->top = 0;
	}

	void feed(block * label, int party, const bool* b, int length) {
		if(party == ALICE) {
			this->shared_prg.random_block(label, length);
			for (int i = 0; i < length; ++i) {
				if(b[i])
					label[i] = label[i] ^ gc->delta;
			}
		} else {
			if (length > this->batch_size) {
				this->ot->send_cot(label, length);
			} else {
				bool * tmp = new bool[length];
				if(length > this->batch_size - this->top) {
					memcpy(label, this->buf + this->top, (this->batch_size-this->top)*sizeof(block));
					int filled = this->batch_size - this->top;
					refill();
					memcpy(label + filled, this->buf, (length - filled)*sizeof(block));
					this->top = (length - filled);
				} else {
					memcpy(label, this->buf+this->top, length*sizeof(block));
					this->top+=length;
				}
				
				this->io->recv_data(tmp, length);
				for (int i = 0; i < length; ++i)
					if(tmp[i])
						label[i] = label[i] ^ gc->delta;
				delete[] tmp;
			}
		}
	}

	void reveal(bool* b, int party, const block * label, int length) {
		if (party == XOR) {
			for (int i = 0; i < length; ++i)
				b[i] = getLSB(label[i]);
			return;
		}
		for (int i = 0; i < length; ++i) {
			bool lsb = getLSB(label[i]);
			if (party == BOB or party == PUBLIC) {
				this->io->send_data(&lsb, 1);
				b[i] = false;
			} else if(party == ALICE) {
				bool tmp;
				this->io->recv_data(&tmp, 1);
				b[i] = (tmp != lsb);
			}
		}
		if(party == PUBLIC)
			this->io->recv_data(b, length);
	}
};
}
#endif //SEMIHONEST_GEN_H__