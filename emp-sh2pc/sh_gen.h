#ifndef EMP_SEMIHONEST_GEN_H__
#define EMP_SEMIHONEST_GEN_H__
#include <memory>
#include "emp-sh2pc/sh_party.h"

namespace emp {

class SemiHonestGen : public HalfGateGen, public SemiHonestParty {
public:
	SemiHonestGen(IOChannel* io_, int batch_sz)
	    : HalfGateGen(io_), SemiHonestParty(io_, batch_sz) {
		// IKNP requires Δ as bool[128] with bit 0 = 1. HalfGateGen's
		// ctor already pinned bit 0 of `delta` via set_bit, so the
		// invariant holds by construction.
		bool delta_bool[128];
		const uint8_t* d = reinterpret_cast<const uint8_t*>(&this->delta);
		for (int i = 0; i < 128; ++i)
			delta_bool[i] = (d[i / 8] >> (i % 8)) & 1;
		ot->setup_send(delta_bool);

		block seed;
		PRG().random_block(&seed, 1);
		io->send_block(&seed, 1);
		shared_prg.reseed(&seed);
		refill();
	}

	void refill() {
		ot->send_cot(buf.get(), batch_size);
		top = 0;
	}

	void feed(void* out, int from_party, const bool* in, size_t length) override {
		block* label = static_cast<block*>(out);
		if (from_party == ALICE) {
			shared_prg.random_block(label, length);
			for (size_t i = 0; i < length; ++i) {
				if (in[i])
					label[i] = label[i] ^ this->delta;
			}
		} else {
			if ((int)length > batch_size) {
				ot->send_cot(label, length);
			} else {
				auto tmp = std::make_unique<bool[]>(length);
				if ((int)length > batch_size - top) {
					memcpy(label, buf.get() + top, (batch_size - top) * sizeof(block));
					int filled = batch_size - top;
					refill();
					memcpy(label + filled, buf.get(), (length - filled) * sizeof(block));
					top = (length - filled);
				} else {
					memcpy(label, buf.get() + top, length * sizeof(block));
					top += length;
				}

				io->recv_data(tmp.get(), length);
				for (size_t i = 0; i < length; ++i) {
					if (tmp[i])
						label[i] = label[i] ^ this->delta;
				}
			}
		}
	}

	void reveal(bool* out, int to_party, const void* in, size_t length) override {
		const block* label = static_cast<const block*>(in);
		if (to_party == XOR) {
			for (size_t i = 0; i < length; ++i)
				out[i] = getLSB(label[i]);
			return;
		}
		for (size_t i = 0; i < length; ++i) {
			bool lsb = getLSB(label[i]);
			if (to_party == BOB or to_party == PUBLIC) {
				io->send_data(&lsb, 1);
				out[i] = false;
			} else if (to_party == ALICE) {
				bool tmp;
				io->recv_data(&tmp, 1);
				out[i] = (tmp != lsb);
			}
		}
		if (to_party == PUBLIC)
			io->recv_data(out, length);
	}
};

}  // namespace emp
#endif
