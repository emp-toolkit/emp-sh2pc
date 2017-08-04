#include "emp-sh2pc/semihonest_gen.h"
#include "emp-sh2pc/semihonest_eva.h"

template<typename IO>
static void setup_semi_honest(IO* io, int party) {
	if(party == ALICE) {
		HalfGateGen<IO>::circ_exec = new HalfGateGen<IO>(io);
		ProtocolExecution::prot_exec = new SemiHonestGen<IO>(io, HalfGateGen<IO>::circ_exec);
	} else {
		HalfGateEva<IO>::circ_exec = new HalfGateEva<IO>(io);
		ProtocolExecution::prot_exec = new SemiHonestEva<IO>(io, HalfGateEva<IO>::circ_exec);
	}
}

