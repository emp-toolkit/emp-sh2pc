#ifndef EMP_SEMIHONEST_EVA_H__
#define EMP_SEMIHONEST_EVA_H__
#include <memory>
#include "emp-sh2pc/sh_party.h"

namespace emp {

class SemiHonestEva : public HalfGateEva, public SemiHonestParty {
public:
	PRG prg;

	SemiHonestEva(IOChannel* io_, int batch_sz)
	    : HalfGateEva(io_), SemiHonestParty(BOB, io_, batch_sz) {
		// IKNP receiver has no Δ; bootstrap fires lazily on first
		// recv_cot inside `refill()` below.
		block seed;
		io->recv_block(&seed, 1);
		shared_prg.reseed(&seed);
		refill();
	}

	void refill() {
		prg.random_bool(buff.get(), batch_size);
		ot->recv_cot(buf.get(), buff.get(), batch_size);
		top = 0;
	}

	void feed(void* out, int from_party, const bool* in, size_t length) override {
		block* label = static_cast<block*>(out);
		if (from_party == ALICE) {
			shared_prg.random_block(label, length);
		} else {
			if ((int)length > batch_size) {
				ot->recv_cot(label, in, length);
			} else {
				auto tmp = std::make_unique<bool[]>(length);
				if ((int)length > batch_size - top) {
					memcpy(label, buf.get() + top, (batch_size - top) * sizeof(block));
					memcpy(tmp.get(), buff.get() + top, (batch_size - top));
					int filled = batch_size - top;
					refill();
					memcpy(label + filled, buf.get(), (length - filled) * sizeof(block));
					memcpy(tmp.get() + filled, buff.get(), length - filled);
					top = length - filled;
				} else {
					memcpy(label, buf.get() + top, length * sizeof(block));
					memcpy(tmp.get(), buff.get() + top, length);
					top += length;
				}

				for (size_t i = 0; i < length; ++i)
					tmp[i] = (tmp[i] != in[i]);
				io->send_data(tmp.get(), length);
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
			bool lsb = getLSB(label[i]), tmp;
			if (to_party == BOB or to_party == PUBLIC) {
				io->recv_data(&tmp, 1);
				out[i] = (tmp != lsb);
			} else if (to_party == ALICE) {
				io->send_data(&lsb, 1);
				out[i] = false;
			}
		}
		if (to_party == PUBLIC)
			io->send_data(out, length);
	}
};

}  // namespace emp
#endif
