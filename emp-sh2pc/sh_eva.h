#ifndef EMP_SEMIHONEST_EVA_H__
#define EMP_SEMIHONEST_EVA_H__
#include <memory>
#include "emp-sh2pc/sh_party.h"

namespace emp {

class SemiHonestEva : public HalfGateEva, public SemiHonestParty {
public:
	SemiHonestEva(IOChannel* io_, int batch_sz)
	    : HalfGateEva(io_), SemiHonestParty(BOB, io_, batch_sz) {
		// IKNP receiver has no Δ; bootstrap fires lazily on first
		// rcot inside `refill()` below.
		block seed;
		io->recv_block(&seed, 1);
		shared_prg.reseed(&seed);
		refill();
	}

	void refill() {
		// RCOT: each buf[i] LSB *is* our random choice bit — IKNP's choice_prg
		// drives it, so we can drop sh_eva's old prg.random_bool and just
		// project the LSBs into buff for the feed-path correction below.
		ot->rcot(buf.get(), batch_size);
		for (int i = 0; i < batch_size; ++i)
			buff[i] = getLSB(buf[i]);
		top = 0;
	}

	void feed(void* out, int from_party, const bool* in, size_t length) override {
		block* label = static_cast<block*>(out);
		if (from_party == ALICE) {
			shared_prg.random_block(label, length);
		} else {
			if ((int)length > batch_size) {
				// RCOT + 1-bit correction: tell Alice how to flip her "0"
				// label so our PRG-derived choice ends up matching Bob's
				// real input.
				ot->rcot(label, length);
				auto tmp = std::make_unique<bool[]>(length);
				for (size_t i = 0; i < length; ++i)
					tmp[i] = (getLSB(label[i]) != in[i]);
				io->send_bool(tmp.get(), length);
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
				io->send_bool(tmp.get(), length);
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
