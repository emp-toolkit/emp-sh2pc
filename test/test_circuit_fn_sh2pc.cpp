// The BooleanContext circuit frontend over the garbled 2PC backend: a circuit
// compiled ONCE (host-side, through a RecordContext) replays identically on the
// live SH2PCContext — compile-once / run-on-any-context. Both parties compile the
// same (deterministic) circuit and replay it in lockstep. C++20.

#include "emp-sh2pc/emp-sh2pc.h"           // NetIO, parse_party_and_port, SH2PCSession/Context
#include "emp-tool/frontend/circuit_fn.h"  // frontend::compile / run + shapes
#include <cstdint>
#include <cstdio>

using namespace emp;
namespace cf = emp::frontend;

using U32 = UInt<SH2PCContext, 32>;
using F32 = Float<SH2PCContext, 32>;

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);

    SH2PCSession sess(&io, party);
    SH2PCContext ctx(sess);
    int fails = 0;

    // Compile once, host-side (no protocol, no I/O): pure circuit functions.
    auto circ_add  = cf::compile<UIntShape<32>, UIntShape<32>>([](auto a, auto b) { return a + b; });
    auto circ_fadd = cf::compile<FloatShape<32>, FloatShape<32>>([](auto a, auto b) { return a + b; });

    // uint32: run the compiled circuit on the live garbled context.
    {
        const uint32_t av = 12345678u, bv = 87654321u;
        U32 a = sess.input<U32>(ctx, ALICE, (uint64_t)av);
        U32 b = sess.input<U32>(ctx, BOB,   (uint64_t)bv);
        U32 c = cf::run(ctx, circ_add, a, b);
        uint32_t r = (uint32_t)sess.reveal(c, PUBLIC);
        if (party == BOB) {
            bool ok = r == (uint32_t)(av + bv);
            printf("  compiled uint32 add over SH2PCContext: %u (expect %u) %s\n",
                   r, (uint32_t)(av + bv), ok ? "OK" : "FAIL");
            fails += !ok;
        }
    }

    // fp32: the compiled circuit inlines the fp32_add.empbc gates; replay garbled.
    {
        F32 a = sess.input<F32>(ctx, ALICE, 1.5f);
        F32 b = sess.input<F32>(ctx, BOB,   2.25f);
        F32 c = cf::run(ctx, circ_fadd, a, b);
        float r = sess.reveal(c, PUBLIC);
        if (party == BOB) {
            bool ok = r == 3.75f;
            printf("  compiled fp32 add over SH2PCContext: %g (expect 3.75) %s\n", r, ok ? "OK" : "FAIL");
            fails += !ok;
        }
    }

    sess.finalize();
    if (party == BOB) printf("test_circuit_fn_sh2pc: %s\n", fails ? "FAILED" : "PASS");
    return fails ? 1 : 0;
}
