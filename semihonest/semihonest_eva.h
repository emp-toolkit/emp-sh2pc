#ifndef SEMIHONEST_EVA_H__
#define SEMIHONEST_EVA_H__
#include <emp-tool>
#include <emp-ot>
#include <iostream>

template<typename T>
void eval_feed(Backend* be, int party, block * label, const bool*, int length);
template<typename T>
void eval_reveal(Backend* be, bool* clear, int party, const block * label, int length);

template<typename T>
class SemiHonestEva: public Backend { public:
	NetIO* io;
	SHOTIterated* ot;
	HalfGateEva<T> * gc;
	SemiHonestEva(NetIO*io, HalfGateEva<T> * gc): Backend(BOB) {
		this->io = io;
		ot = new SHOTIterated(io, false);
		this->gc = gc;	
		Feed_internal = eval_feed<T>;
		Reveal_internal = eval_reveal<T>;
	}
	~SemiHonestEva() {
		delete ot;
	}
};


template<typename T>
void eval_feed(Backend* be, int party, block * label, const bool* b, int length) {
	SemiHonestEva<T> * backend = (SemiHonestEva<T>*)(be);
	if(party == ALICE) {
		backend->io->recv_block(label, length);
	} else {
		backend->ot->recv_cot(label, b, length);
	}
}

template<typename T>
void eval_reveal(Backend* be, bool * b, int party, const block * label, int length) {
	SemiHonestEva<T> * backend = (SemiHonestEva<T>*)(be);
	block tmp;
	for (int i = 0; i < length; ++i) {
		if(isOne(&label[i]))
			b[i] = true;
		else if (isZero(&label[i]))
			b[i] = false;
		else {
			if (party == BOB or party == PUBLIC) {
				backend->io->recv_block(&tmp, 1);
				b[i] = !(block_cmp(&tmp, &label[i], 1));
			} else if (party == ALICE) {
				backend->io->send_block(&label[i], 1);
				b[i] = false;
			}
		}
	}
	if(party == PUBLIC)
		backend->io->send_data(b, length);
}
#endif// GARBLE_CIRCUIT_SEMIHONEST_H__