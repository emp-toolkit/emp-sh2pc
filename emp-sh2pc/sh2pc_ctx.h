#ifndef EMP_SH2PC_CTX_H__
#define EMP_SH2PC_CTX_H__

// SH2PCCtx — the semi-honest 2PC gate context (SH2PCSession::DirectCtx). It is a C++20
// BooleanContext: gate ops return garbled-label wires (AND via the half-gate
// garble/eval, XOR/NOT/const over labels). Gates are eager — an AND garbles or
// evaluates one half-gate over the network as it is called — so the context is
// bound by its owning SH2PCSession to the protocol primitives it garbles against
// (party, IO channel, Delta, the public-constant labels, and the shared MITCCRH).
// It owns no I/O policy and no input/reveal surface; those live on the Session.

#include "emp-tool/runtime/runtime.h"
#include "emp-tool/ir/context/context.h"        // BooleanContext
#include "emp-tool/runtime/execution/half_gate.h"    // halfgates_garble / halfgates_eval
#include "emp-tool/runtime/crypto/mitccrh.h"

namespace emp {

class SH2PCCtx {
public:
    // The wire IS the live garbled label: block (__m128i) is semiregular, which
    // is all BooleanContext requires, so no wrapper type is needed.
    using Wire = block;

    // Default-constructed contexts are inert; SH2PCSession binds a usable one (via
    // bind_) once its handshake has fixed Delta, the constant labels, and MITCCRH.
    SH2PCCtx() = default;

    // ---- BooleanContext gate ops (value-return; drive the typed values) ----
    Wire public_bit(bool b)       { return constant_[b ? 1 : 0]; }
    Wire xor_gate(Wire a, Wire b) { return a ^ b; }
    Wire not_gate(Wire a)         { return a ^ constant_[1]; }
    Wire and_gate(Wire a, Wire b) {
        if (party_ == ALICE) {
            block table[2];
            block w = halfgates_garble(a, a ^ delta_,
                                       b, b ^ delta_, delta_, table, mitccrh_);
            io_->send_block(table, 2);
            return w;
        } else {
            block table[2];
            io_->recv_block(table, 2);
            return halfgates_eval(a, b, table, mitccrh_);
        }
    }

private:
    friend class SH2PCSession;
    // Bind to the owning session's protocol primitives. party / io / delta /
    // constant are fixed once (after the session handshake) and copied by value;
    // mitccrh is shared by pointer (the session owns it, gid advances per AND).
    void bind_(int party, IOChannel* io, block delta, const block constant[2], MITCCRH<8>* mitccrh) {
        party_ = party;
        io_ = io;
        delta_ = delta;
        constant_[0] = constant[0];
        constant_[1] = constant[1];
        mitccrh_ = mitccrh;
    }

    int party_ = 0;
    IOChannel* io_ = nullptr;
    block delta_{};               // meaningful for ALICE (the garbler)
    block constant_[2]{};         // public-constant labels (false, true)
    MITCCRH<8>* mitccrh_ = nullptr;
};

static_assert(BooleanContext<SH2PCCtx>);

}  // namespace emp
#endif  // EMP_SH2PC_CTX_H__
