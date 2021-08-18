#ifndef EMP_SEMIHONEST_EVA_H__
#define EMP_SEMIHONEST_EVA_H__
#include "emp-sh2pc/sh_party.h"

namespace emp {
template<typename IO>
class SemiHonestEva: public SemiHonestGarbledCircuit,
	public HalfGateEva<IO>  { public:
	IKNP<IO> * ot = nullptr;
	PRG prg;
	SemiHonestEva(IO *io): HalfGateEva<IO>(io) {
		ot = new IKNP<IO>(this->io);
		this->ot->setup_recv();
		block seed; this->io->recv_block(&seed, 1);
		this->shared_prg.reseed(&seed);
		refill();
	}

	~SemiHonestEva() {
		if(ot != nullptr)
			delete ot;
	}

	void refill() {
		prg.random_bool(this->buff, this->batch_size);
		this->ot->recv_cot(this->buf, this->buff, this->batch_size);
		this->top = 0;
	}

	void feed(void * in, int party, const bool* b, size_t length) override {
		block * label = (block *)in;
		if(party == ALICE) {
			this->shared_prg.random_block(label, length);
		} else {
			if (length > this->batch_size) {
				this->ot->recv_cot(label, b, length);
			} else {
				bool * tmp = new bool[length];
				if(length > this->batch_size - this->top) {
					memcpy(label, this->buf + this->top, (this->batch_size-this->top)*sizeof(block));
					memcpy(tmp, this->buff + this->top, (this->batch_size-this->top));
					int filled = this->batch_size - this->top;
					refill();
					memcpy(label+filled, this->buf, (length - filled)*sizeof(block));
					memcpy(tmp+ filled, this->buff, length - filled);
					this->top = length - filled;
				} else {
					memcpy(label, this->buf+this->top, length*sizeof(block));
					memcpy(tmp, this->buff+this->top, length);
					this->top+=length;
				}

				for(int i = 0; i < length; ++i)
					tmp[i] = (tmp[i] != b[i]); 
				this->io->send_data(tmp, length);

				delete[] tmp;
			}
		}
	}

	void reveal(bool* b, int party, const void * in, size_t length) override {
		const block * label = (const block *)in;
		if (party == XOR) {
			for (int i = 0; i < length; ++i)
				b[i] = getLSB(label[i]);
			return;
		}
		for (int i = 0; i < length; ++i) {
			bool lsb = getLSB(label[i]), tmp;
			if (party == BOB or party == PUBLIC) {
				this->io->recv_data(&tmp, 1);
				b[i] = (tmp != lsb);
			} else if (party == ALICE) {
				this->io->send_data(&lsb, 1);
				b[i] = false;
			}
		}
		if(party == PUBLIC)
			this->io->send_data(b, length);
	}

};
}

#endif// GARBLE_CIRCUIT_SEMIHONEST_H__