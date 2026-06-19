// The BooleanContext circuit frontend over the garbled 2PC backend: a circuit
// compiled ONCE (host-side, through a RecordCtx) replays identically on the
// live SH2PCSession context — compile-once / run-on-any-context. Both parties compile the
// same (deterministic) circuit and replay it in lockstep. C++20.

#include "emp-sh2pc/emp-sh2pc.h"           // NetIO, parse_party, SH2PCSession
#include "emp-tool/circuits/frontend/circuit_fn.h"  // frontend::compile / run
#include "emp-tool/circuits/frontend/rec.h"         // rec::UInt / rec::Float shapes
#include <cstdint>
#include <cstdio>

using namespace emp;
namespace cf = emp::frontend;

using U32 = UInt_T<SH2PCSession::ctx_t, 32>;
using F32 = Float_T<SH2PCSession::ctx_t, 32>;

int main(int argc, char** argv) {
    int port, party;
    party = parse_party(argv);
    port = peer_port();
    auto io = (party == ALICE) ? NetIO::listen(port) : NetIO::connect(peer_ip(), port);

    SH2PCSession sess(io.get(), party);
    int fails = 0;

    // Compile once, host-side (no protocol, no I/O): pure circuit functions.
    auto circ_add  = cf::compile<rec::UInt<32>, rec::UInt<32>>([](auto a, auto b) { return a + b; });
    auto circ_fadd = cf::compile<rec::Float<32>, rec::Float<32>>([](auto a, auto b) { return a + b; });

    // uint32: run the compiled circuit on the live garbled context.
    {
        const uint32_t av = 12345678u, bv = 87654321u;
        U32 a = sess.input<U32>(ALICE, (uint64_t)av);
        U32 b = sess.input<U32>(BOB,   (uint64_t)bv);
        U32 c = cf::run(sess.ctx(), circ_add, a, b);
        uint32_t r = (uint32_t)sess.reveal(c, PUBLIC).value();
        if (party == BOB) {
            bool ok = r == (uint32_t)(av + bv);
            printf("  compiled uint32 add over SH2PCCtx: %u (expect %u) %s\n",
                   r, (uint32_t)(av + bv), ok ? "OK" : "FAIL");
            fails += !ok;
        }
    }

    // fp32: the compiled circuit inlines the fp32_add.empbc gates; replay garbled.
    {
        F32 a = sess.input<F32>(ALICE, 1.5f);
        F32 b = sess.input<F32>(BOB,   2.25f);
        F32 c = cf::run(sess.ctx(), circ_fadd, a, b);
        float r = sess.reveal(c, PUBLIC).value();
        if (party == BOB) {
            bool ok = r == 3.75f;
            printf("  compiled fp32 add over SH2PCCtx: %g (expect 3.75) %s\n", r, ok ? "OK" : "FAIL");
            fails += !ok;
        }
    }

    sess.finalize();
    if (party == BOB) printf("test_circuit_fn_sh2pc: %s\n", fails ? "FAILED" : "PASS");
    return fails ? 1 : 0;
}
