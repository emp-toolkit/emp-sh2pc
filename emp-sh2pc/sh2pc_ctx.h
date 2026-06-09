#ifndef EMP_SH2PC_CTX_H__
#define EMP_SH2PC_CTX_H__

// SH2PCCtx — the semi-honest 2PC gate context (SH2PCSession::Ctx). It is a C++20
// BooleanContext: gate ops return garbled-label wires (AND via the half-gate
// garble/eval, XOR/NOT/const over labels). Gates are eager — an AND garbles or
// evaluates one half-gate over the network as it is called — so the context is
// bound by its owning SH2PCSession to the protocol primitives it garbles against
// (party, IO channel, Delta, the public-constant labels, and the shared MITCCRH).
// It owns no I/O policy and no input/reveal surface; those live on the Session.

#include "emp-tool/emp-tool.h"
#include "emp-tool/context/context.h"        // BooleanContext
#include "emp-tool/execution/half_gate.h"    // halfgates_garble / halfgates_eval
#include "emp-tool/crypto/mitccrh.h"
#include <cstring>

namespace emp {

// Garbled-label wire, wrapped so it is std::regular (a raw block is not).
struct SHWire {
    block label{};
    bool operator==(const SHWire& r) const { return std::memcmp(&label, &r.label, sizeof(block)) == 0; }
    bool operator!=(const SHWire& r) const { return !(*this == r); }
};

class SH2PCCtx {
public:
    using Wire = SHWire;

    // Default-constructed contexts are inert; SH2PCSession binds a usable one (via
    // bind_) once its handshake has fixed Delta, the constant labels, and MITCCRH.
    SH2PCCtx() = default;

    // ---- BooleanContext gate ops (value-return; drive the typed values) ----
    Wire public_bit(bool b)       { return SHWire{ constant_[b ? 1 : 0] }; }
    Wire xor_gate(Wire a, Wire b) { return SHWire{ a.label ^ b.label }; }
    Wire not_gate(Wire a)         { return SHWire{ a.label ^ constant_[1] }; }
    Wire and_gate(Wire a, Wire b) {
        if (party_ == ALICE) {
            block table[2];
            block w = halfgates_garble(a.label, a.label ^ delta_,
                                       b.label, b.label ^ delta_, delta_, table, mitccrh_);
            io_->send_block(table, 2);
            return SHWire{ w };
        } else {
            block table[2];
            io_->recv_block(table, 2);
            return SHWire{ halfgates_eval(a.label, b.label, table, mitccrh_) };
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
