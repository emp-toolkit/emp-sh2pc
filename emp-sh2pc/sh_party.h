#ifndef EMP_SH_PARTY_H__
#define EMP_SH_PARTY_H__
#include <memory>
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"

namespace emp {

// Shared semi-honest plumbing held by both SemiHonestGen (sender / Alice)
// and SemiHonestEva (receiver / Bob): the IKNP COT extension instance,
// the synchronized PRG used to derive Alice-input labels deterministically
// on both sides, and a refill buffer of preprocessed COT outputs that
// `feed` consumes for non-circuit-input wires.
//
// Held as a non-Backend helper base. The role-specific derived classes
// multiply-inherit from HalfGate{Gen,Eva} (which IS the Backend) and
// from this helper, so a single object plays both the gate-engine role
// and the input/output OT role.
class SemiHonestParty {
public:
	// `io` is NOT held here: SemiHonest{Gen,Eva} multiply-inherit from
	// HalfGate{Gen,Eva}, which already owns `IOChannel* io`. Storing a
	// second copy would create a diamond ambiguity at every io-> use
	// inside feed / reveal.
	std::unique_ptr<IKNP> ot;
	PRG shared_prg;

	std::unique_ptr<block[]> buf;
	std::unique_ptr<bool[]>  buff;
	int top = 0;
	int batch_size;

	SemiHonestParty(IOChannel* io_, int batch_sz)
	    : ot(std::make_unique<IKNP>(io_, /*malicious=*/false)),
	      buf(std::make_unique<block[]>(batch_sz)),
	      buff(std::make_unique<bool[]>(batch_sz)),
	      batch_size(batch_sz) {}

	void set_batch_size(int size) {
		batch_size = size;
		buf  = std::make_unique<block[]>(size);
		buff = std::make_unique<bool[]>(size);
	}
};

}  // namespace emp
#endif
