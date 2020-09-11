#ifndef EMP_SH_PARTY_H__
#define EMP_SH_PARTY_H__
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"

namespace emp {

template<typename IO>
class SemiHonestParty: public ProtocolExecution { public:
	IO* io = nullptr;
	IKNP<IO> * ot = nullptr;
	PRG shared_prg;

	block * buf = nullptr;
	bool * buff = nullptr;
	int top = 0;
	int batch_size = 1024*16;

	SemiHonestParty(IO * io, int party) : ProtocolExecution(party) {
		this->io = io;
		ot = new IKNP<IO>(io);
		buf = new block[batch_size];
		buff = new bool[batch_size];
	}
	void set_batch_size(int size) {
		delete[] buf;
		delete[] buff;
		batch_size = size;
		buf = new block[batch_size];
		buff = new bool[batch_size];
	}

	~SemiHonestParty() {
		delete[] buf;
		delete[] buff;
		delete ot;
	}
};
}
#endif
