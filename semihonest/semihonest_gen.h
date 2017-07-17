#ifndef SEMIHONEST_GEN_H__
#define SEMIHONEST_GEN_H__
#include <emp-tool>
#include <emp-ot>
#include <iostream>

template<typename IO>
void gen_feed(Backend* be, int party, block * label, const bool*, int length);
template<typename IO>
void gen_reveal(Backend* be, bool* clear, int party, const block * label, int length);

template<typename IO>
class SemiHonestGen: public Backend { public:
	IO* io;
	SHOTExtension<IO> * ot;
	PRG prg, shared_prg;
	HalfGateGen<IO> * gc;
	SemiHonestGen(IO* io, HalfGateGen<IO>* gc): Backend(ALICE) {
		this->io = io;
		ot = new SHOTExtension<IO>(io);
		this->gc = gc;	
		Feed_internal = gen_feed<IO>;
		Reveal_internal = gen_reveal<IO>;
		block seed;prg.random_block(&seed, 1);
		io->send_block(&seed, 1);
		shared_prg.reseed(&seed);
	}
	~SemiHonestGen() {
		delete ot;
	}
};

template<typename IO>
void gen_feed(Backend* be, int party, block * label, const bool* b, int length) {
	SemiHonestGen<IO> * backend = (SemiHonestGen<IO>*)(be);
	if(party == ALICE) {
		backend->shared_prg.random_block(label, length);
		for (int i = 0; i < length; ++i) {
			if(b[i])
				label[i] = xorBlocks(label[i], backend->gc->delta);
		}
	} else {
		backend->ot->send_cot(label, backend->gc->delta, length);
	}
}

template<typename IO>
void gen_reveal(Backend* be, bool* b, int party, const block * label, int length) {
	SemiHonestGen<IO> * backend = (SemiHonestGen<IO>*)(be);
	for (int i = 0; i < length; ++i) {
		if(isOne(&label[i]))
			b[i] = true;
		else if (isZero(&label[i]))
			b[i] = false;
		else {
			if (party == BOB or party == PUBLIC) {
				backend->io->send_block(&label[i], 1);
				b[i] = false;
			} else if(party == ALICE) {
				block tmp;
				backend->io->recv_block(&tmp, 1);
				b[i] = !(block_cmp(&tmp, &label[i], 1));
			}
		}
	}
	if(party == PUBLIC)
		backend->io->recv_data(b, length);
}
#endif //SEMIHONEST_GEN_H__