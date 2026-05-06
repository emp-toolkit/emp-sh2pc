#ifndef EMP_SEMIHONEST_H__
#define EMP_SEMIHONEST_H__
#include "emp-sh2pc/sh_gen.h"
#include "emp-sh2pc/sh_eva.h"

namespace emp {

inline SemiHonestParty* setup_semi_honest(IOChannel* io, int party,
                                          int batch_size = 1024 * 16) {
	if (party == ALICE) {
		auto* g = new SemiHonestGen(io, batch_size);
		backend = g;
		return static_cast<SemiHonestParty*>(g);
	} else {
		auto* e = new SemiHonestEva(io, batch_size);
		backend = e;
		return static_cast<SemiHonestParty*>(e);
	}
}

inline void finalize_semi_honest() {
	if (!backend) return;
	backend->finalize();
	delete backend;
	backend = nullptr;
}

}  // namespace emp
#endif
