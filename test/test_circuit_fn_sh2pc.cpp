// The BooleanContext circuit frontend over the garbled 2PC backend: a circuit
// compiled ONCE (host-side, through a RecordCtx) replays identically on the
// live SH2PCCtx — compile-once / run-on-any-context. Both parties compile the
// same (deterministic) circuit and replay it in lockstep. C++20.

#include "emp-sh2pc/emp-sh2pc.h"           // NetIO, parse_party_and_port, SH2PCCtx
#include "emp-tool/frontend/circuit_fn.h"  // frontend::compile / run
#include "emp-tool/frontend/rec.h"         // rec::UInt / rec::Float shapes
#include <cstdint>
#include <cstdio>

using namespace emp;
namespace cf = emp::frontend;

using U32 = UInt_T<SH2PCCtx, 32>;
using F32 = Float_T<SH2PCCtx, 32>;

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);

    SH2PCCtx ctx(&io, party);
    int fails = 0;

    // Compile once, host-side (no protocol, no I/O): pure circuit functions.
    auto circ_add  = cf::compile<rec::UInt<32>, rec::UInt<32>>([](auto a, auto b) { return a + b; });
    auto circ_fadd = cf::compile<rec::Float<32>, rec::Float<32>>([](auto a, auto b) { return a + b; });

    // uint32: run the compiled circuit on the live garbled context.
    {
        const uint32_t av = 12345678u, bv = 87654321u;
        U32 a = ctx.input<U32>(ALICE, (uint64_t)av);
        U32 b = ctx.input<U32>(BOB,   (uint64_t)bv);
        U32 c = cf::run(ctx, circ_add, a, b);
        uint32_t r = (uint32_t)ctx.reveal(c, PUBLIC);
        if (party == BOB) {
            bool ok = r == (uint32_t)(av + bv);
            printf("  compiled uint32 add over SH2PCCtx: %u (expect %u) %s\n",
                   r, (uint32_t)(av + bv), ok ? "OK" : "FAIL");
            fails += !ok;
        }
    }

    // fp32: the compiled circuit inlines the fp32_add.empbc gates; replay garbled.
    {
        F32 a = ctx.input<F32>(ALICE, 1.5f);
        F32 b = ctx.input<F32>(BOB,   2.25f);
        F32 c = cf::run(ctx, circ_fadd, a, b);
        float r = ctx.reveal(c, PUBLIC);
        if (party == BOB) {
            bool ok = r == 3.75f;
            printf("  compiled fp32 add over SH2PCCtx: %g (expect 3.75) %s\n", r, ok ? "OK" : "FAIL");
            fails += !ok;
        }
    }

    ctx.finalize();
    if (party == BOB) printf("test_circuit_fn_sh2pc: %s\n", fails ? "FAILED" : "PASS");
    return fails ? 1 : 0;
}
