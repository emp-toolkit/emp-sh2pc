#ifndef SEMIHONEST_GEN_H__
#define SEMIHONEST_GEN_H__
#include <emp-tool>
#include <emp-ot>
#include <iostream>

template<typename T>
void gen_feed(Backend* be, int party, block * label, const bool*, int length);
template<typename T>
void gen_reveal(Backend* be, bool* clear, int party, const block * label, int length);

template<typename T>
class SemiHonestGen: public Backend { public:
	NetIO* io;
	SHOTIterated * ot;
	PRG prg;
	HalfGateGen<T> * gc;
	SemiHonestGen(NetIO* io, HalfGateGen<T>* gc): Backend(ALICE) {
		this->io = io;
		ot = new SHOTIterated(io, true);

		this->gc = gc;	
		Feed_internal = gen_feed<T>;
		Reveal_internal = gen_reveal<T>;
	}

	~SemiHonestGen() {
		delete ot;
	}
};

template<typename T>
void gen_feed(Backend* be, int party, block * label, const bool* b, int length) {
	SemiHonestGen<T> * backend = (SemiHonestGen<T>*)(be);
	if(party == ALICE) {
		backend->prg.random_block(label, length);
		for (int i = 0; i < length; ++i) {
			block tosend = label[i];
			if(b[i]) tosend = xorBlocks(tosend, backend->gc->delta);
			backend->io->send_block(&tosend, 1);
		}
	} else {
		backend->ot->send_cot(label, backend->gc->delta, length);
	}
}

template<typename T>
void gen_reveal(Backend* be, bool* b, int party, const block * label, int length) {
	SemiHonestGen<T> * backend = (SemiHonestGen<T>*)(be);
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