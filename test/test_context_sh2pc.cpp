// A BooleanContext-templated circuit running on the garbled 2PC backend through
// SH2PCSession (sh2pc_session.h) — no global emp::backend, no Backend virtual
// dispatch; AND gates go straight to halfgates_garble/eval, and typed
// input<T>()/reveal<T>() own the OT. Demonstrates a templated integer kernel and
// an IR-replay float builtin. C++20.

#include "emp-sh2pc/emp-sh2pc.h"          // NetIO, parse_party_and_port, ALICE/BOB
#include "emp-sh2pc/sh2pc_session.h"      // SH2PCSession
#include "emp-tool/circuits/typed.h"
#include <cstdint>
#include <cstdio>

using namespace emp;

int main(int argc, char** argv) {
    int port, party;
    parse_party_and_port(argv, &party, &port);
    NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);

    SH2PCSession sess(&io, party);              // owns crypto/IO/OT/Delta — no global backend
    int fails = 0;

    // 1) keep-templated kernel: UInt32 add (ALICE owns a, BOB owns b).
    {
        const uint32_t av = 12345678u, bv = 87654321u;
        auto a = sess.input<UInt_T<SH2PCSession::DirectCtx, 32>>(ALICE, (uint64_t)av);
        auto b = sess.input<UInt_T<SH2PCSession::DirectCtx, 32>>(BOB,   (uint64_t)bv);
        auto c = a + b;
        uint32_t r = (uint32_t)sess.reveal(c, PUBLIC).value();
        if (party == BOB) {
            bool ok = r == (uint32_t)(av + bv);
            printf("  uint32 add (templated kernel, native session): %u (expect %u) %s\n",
                   r, (uint32_t)(av + bv), ok ? "OK" : "FAIL");
            fails += !ok;
        }
    }

    // 2) IR-replay builtin: fp32 add (fp32_add.empbc) through the native context.
    {
        auto a = sess.input<Float_T<SH2PCSession::DirectCtx, 32>>(ALICE, 1.5f);
        auto b = sess.input<Float_T<SH2PCSession::DirectCtx, 32>>(BOB,   2.25f);
        auto c = a + b;
        float r = sess.reveal(c, PUBLIC).value();
        if (party == BOB) {
            bool ok = r == 3.75f;
            printf("  float32 add (IR-replay builtin, native session): %g (expect 3.75) %s\n",
                   r, ok ? "OK" : "FAIL");
            fails += !ok;
        }
    }

    // 3) PUBLIC input is a public constant (no OT): a + b + PUBLIC(k).
    {
        const uint32_t av = 1000u, bv = 2000u, kv = 333u;
        auto a = sess.input<UInt_T<SH2PCSession::DirectCtx, 32>>(ALICE,  (uint64_t)av);
        auto b = sess.input<UInt_T<SH2PCSession::DirectCtx, 32>>(BOB,    (uint64_t)bv);
        auto k = sess.input<UInt_T<SH2PCSession::DirectCtx, 32>>(PUBLIC, (uint64_t)kv);
        uint32_t r = (uint32_t)sess.reveal(a + b + k, PUBLIC).value();
        if (party == BOB) {
            bool ok = r == (uint32_t)(av + bv + kv);
            printf("  uint32 PUBLIC-const input (a+b+k): %u (expect %u) %s\n",
                   r, (uint32_t)(av + bv + kv), ok ? "OK" : "FAIL");
            fails += !ok;
        }
    }

    sess.finalize();
    if (party == BOB) printf("test_context_sh2pc (native single-object context): %s\n", fails ? "FAILED" : "PASS");
    return fails ? 1 : 0;
}
