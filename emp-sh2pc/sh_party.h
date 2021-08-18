#ifndef EMP_SH_PARTY_H__
#define EMP_SH_PARTY_H__
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"

namespace emp {

class SemiHonestGarbledCircuit { public:
	typedef block wire_t;
	PRG shared_prg;
	block * buf = nullptr;
	bool * buff = nullptr;
	int top = 0;
	int batch_size = 1024*16;
	SemiHonestGarbledCircuit() {
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

	~SemiHonestGarbledCircuit() {
		delete[] buf;
		delete[] buff;
	}
};
}
#endif
