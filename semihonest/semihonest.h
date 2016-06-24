#include "semihonest_gen.h"
#include "semihonest_eva.h"

static void setup_semi_honest(NetIO* io, int party) {
	if(party == ALICE) {
		local_gc = new HalfGateGen<NetIO>(io);
		local_backend = new SemiHonestGen<NetIO>(io, (HalfGateGen<NetIO, RTCktOpt::on>*)local_gc);
	} else {
		local_gc = new HalfGateEva<NetIO>(io);
		local_backend = new SemiHonestEva<NetIO>(io, (HalfGateEva<NetIO, RTCktOpt::on>*)local_gc);
	}
}

