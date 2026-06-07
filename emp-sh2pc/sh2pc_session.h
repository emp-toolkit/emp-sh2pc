#ifndef EMP_SH2PC_SESSION_H__
#define EMP_SH2PC_SESSION_H__

// Native semi-honest 2PC Session + Context for the BooleanContext model.
// SH2PCSession owns ALL protocol state — IO, IKNP-OT, Delta, the synchronized
// PRG, the half-gate MITCCRH/constants, and the COT refill buffer — plus typed
// input<T>() / reveal<T>(). SH2PCContext borrows the session and realizes the
// BooleanContext gate ops directly (value-return, no global emp::backend, no
// Backend virtual dispatch): AND via halfgates_garble/eval, XOR/NOT/const over
// the session's labels. This is the sole semi-honest path: the old
// SemiHonestGen/Eva diamond and setup_semi_honest global-backend installer have
// been removed.
//
// Encapsulation: the protocol fields are private. The only intentional API is
// party(), num_and(), input/reveal, and the raw bit I/O. SH2PCContext is a
// friend (it reads delta/constants/mitccrh/io to garble); the session is a
// friend of the context (to bounds-check that a typed value/context belongs to
// THIS session before touching the wire/protocol).

#include "emp-tool/emp-tool.h"
#include "emp-tool/circuits/context.h"
#include "emp-tool/circuits/typed.h"
#include "emp-tool/execution/half_gate.h"   // halfgates_garble / halfgates_eval
#include "emp-tool/crypto/mitccrh.h"
#include "emp-ot/emp-ot.h"
#include <cstring>
#include <memory>
#include <vector>

namespace emp {

// Garbled-label wire, wrapped so it is std::regular (raw block is not).
struct SHWire {
    block label{};
    bool operator==(const SHWire& r) const { return std::memcmp(&label, &r.label, sizeof(block)) == 0; }
    bool operator!=(const SHWire& r) const { return !(*this == r); }
};

class SH2PCContext;   // fwd

class SH2PCSession {
public:
    SH2PCSession(IOChannel* io, int party, int batch_sz = 1024 * 16)
        : party_(party), io_(io), batch_size_(batch_sz) {
        if (party_ == ALICE) {
            block tmp[2];
            PRG().random_block(tmp, 2);
            delta_ = set_bit(tmp[0], 0);
            PRG().random_block(constant_, 2);
            io_->send_block(constant_, 2);
            constant_[1] = constant_[1] ^ delta_;
            io_->send_block(tmp + 1, 1);
            mitccrh_.setS(tmp[1]);
            ot_ = std::make_unique<IKNP>(ALICE, io_, /*malicious=*/false);
            bool db[128];
            const uint8_t* d = reinterpret_cast<const uint8_t*>(&delta_);
            for (int i = 0; i < 128; ++i) db[i] = (d[i / 8] >> (i % 8)) & 1;
            ot_->set_delta(db);
            block seed; PRG().random_block(&seed, 1);
            io_->send_block(&seed, 1);
            shared_prg_.reseed(&seed);
        } else {
            io_->recv_block(constant_, 2);
            block tmp; io_->recv_block(&tmp, 1);
            mitccrh_.setS(tmp);
            ot_ = std::make_unique<IKNP>(BOB, io_, /*malicious=*/false);
            block seed; io_->recv_block(&seed, 1);
            shared_prg_.reseed(&seed);
        }
        buf_  = std::make_unique<block[]>(batch_size_);
        buff_ = std::make_unique<bool[]>(batch_size_);
        refill_();
    }

    void finalize() {}

    int party() const { return party_; }
    // AND-gate count so far (mitccrh advances gid by 2 per garbled AND).
    uint64_t num_and() const { return mitccrh_.gid / 2; }

    // ---- typed I/O (the only way values enter/leave a circuit) ----
    template <class T, class Clear>
    T input(SH2PCContext& ctx, int owner, Clear clear);
    template <class T>
    auto reveal(const T& v, int recipient);

    // ---- raw-bit I/O: width-agnostic, for values past the 64-bit clear codec
    // (e.g. 128-bit AES blocks) or hand-assembled wire vectors. ----
    std::vector<SHWire> input_bits(int owner, const bool* in, size_t n) {
        std::vector<block> lab(n);
        feed_(lab.data(), owner, in, n);
        std::vector<SHWire> r(n);
        for (size_t i = 0; i < n; ++i) r[i].label = lab[i];
        return r;
    }
    void reveal_bits(bool* out, int recipient, const SHWire* w, size_t n) {
        std::vector<block> lab(n);
        for (size_t i = 0; i < n; ++i) lab[i] = w[i].label;
        reveal_(out, recipient, lab.data(), n);
    }

private:
    friend class SH2PCContext;

    int party_;
    IOChannel* io_;
    block constant_[2];
    block delta_{};                       // meaningful for ALICE (the garbler)
    MITCCRH<8> mitccrh_;
    std::unique_ptr<IKNP> ot_;
    PRG shared_prg_;
    std::unique_ptr<block[]> buf_;
    std::unique_ptr<bool[]>  buff_;
    int top_ = 0;
    int batch_size_;

    void refill_() {
        ot_->rcot(buf_.get(), batch_size_);
        if (party_ == BOB)
            for (int i = 0; i < batch_size_; ++i) buff_[i] = getLSB(buf_[i]);
        top_ = 0;
    }

    // feed `length` input bits owned by `from_party` into `label` (block labels).
    // PUBLIC is a public constant (both parties build the same constant labels, no
    // OT — neither party's value can override it); ALICE/BOB are private inputs
    // (faithful merge of SemiHonestGen::feed / SemiHonestEva::feed).
    void feed_(block* label, int from_party, const bool* in, size_t length) {
        if (from_party == PUBLIC) {
            for (size_t i = 0; i < length; ++i) label[i] = constant_[in[i] ? 1 : 0];
            return;
        }
        if (from_party != ALICE && from_party != BOB)
            error("SH2PCSession: input owner must be ALICE, BOB, or PUBLIC");
        if (party_ == ALICE) {
            if (from_party == ALICE) {
                shared_prg_.random_block(label, length);
                for (size_t i = 0; i < length; ++i) if (in[i]) label[i] = label[i] ^ delta_;
            } else {
                auto tmp = std::make_unique<bool[]>(length);
                if ((int)length > batch_size_) {
                    ot_->rcot(label, length);
                } else if ((int)length > batch_size_ - top_) {
                    std::memcpy(label, buf_.get() + top_, (batch_size_ - top_) * sizeof(block));
                    int filled = batch_size_ - top_;
                    refill_();
                    std::memcpy(label + filled, buf_.get(), (length - filled) * sizeof(block));
                    top_ = (int)(length - filled);
                } else {
                    std::memcpy(label, buf_.get() + top_, length * sizeof(block));
                    top_ += (int)length;
                }
                io_->recv_bool(tmp.get(), length);
                for (size_t i = 0; i < length; ++i) if (tmp[i]) label[i] = label[i] ^ delta_;
            }
        } else {  // BOB
            if (from_party == ALICE) {
                shared_prg_.random_block(label, length);
            } else {
                auto tmp = std::make_unique<bool[]>(length);
                if ((int)length > batch_size_) {
                    ot_->rcot(label, length);
                    for (size_t i = 0; i < length; ++i) tmp[i] = (getLSB(label[i]) != in[i]);
                } else if ((int)length > batch_size_ - top_) {
                    std::memcpy(label, buf_.get() + top_, (batch_size_ - top_) * sizeof(block));
                    std::memcpy(tmp.get(), buff_.get() + top_, (batch_size_ - top_));
                    int filled = batch_size_ - top_;
                    refill_();
                    std::memcpy(label + filled, buf_.get(), (length - filled) * sizeof(block));
                    std::memcpy(tmp.get() + filled, buff_.get(), length - filled);
                    top_ = (int)(length - filled);
                    for (size_t i = 0; i < length; ++i) tmp[i] = (tmp[i] != in[i]);
                } else {
                    std::memcpy(label, buf_.get() + top_, length * sizeof(block));
                    std::memcpy(tmp.get(), buff_.get() + top_, length);
                    top_ += (int)length;
                    for (size_t i = 0; i < length; ++i) tmp[i] = (tmp[i] != in[i]);
                }
                io_->send_bool(tmp.get(), length);
            }
        }
    }

    // Faithful merge of SemiHonestGen::reveal / SemiHonestEva::reveal.
    void reveal_(bool* out, int to_party, const block* label, size_t length) {
        if (to_party == XOR) {
            for (size_t i = 0; i < length; ++i) out[i] = getLSB(label[i]);
            return;
        }
        if (party_ == ALICE) {
            for (size_t i = 0; i < length; ++i) {
                bool lsb = getLSB(label[i]);
                if (to_party == BOB || to_party == PUBLIC) { io_->send_data(&lsb, 1); out[i] = false; }
                else if (to_party == ALICE) { bool t; io_->recv_data(&t, 1); out[i] = (t != lsb); }
            }
            if (to_party == PUBLIC) io_->recv_data(out, length);
        } else {
            for (size_t i = 0; i < length; ++i) {
                bool lsb = getLSB(label[i]), t;
                if (to_party == BOB || to_party == PUBLIC) { io_->recv_data(&t, 1); out[i] = (t != lsb); }
                else if (to_party == ALICE) { io_->send_data(&lsb, 1); out[i] = false; }
            }
            if (to_party == PUBLIC) io_->send_data(out, length);
        }
    }
};

// BooleanContext over the session — no global backend, no virtual dispatch.
class SH2PCContext {
public:
    using Wire = SHWire;
    explicit SH2PCContext(SH2PCSession& sess) : s(&sess) {}

    Wire public_bit(bool b)        { return SHWire{ s->constant_[b] }; }
    Wire xor_gate(Wire a, Wire b)  { return SHWire{ a.label ^ b.label }; }
    Wire not_gate(Wire a)          { return SHWire{ a.label ^ s->constant_[1] }; }
    Wire and_gate(Wire a, Wire b)  {
        if (s->party_ == ALICE) {
            block table[2];
            block w = halfgates_garble(a.label, a.label ^ s->delta_,
                                       b.label, b.label ^ s->delta_, s->delta_, table, &s->mitccrh_);
            s->io_->send_block(table, 2);
            return SHWire{ w };
        } else {
            block table[2];
            s->io_->recv_block(table, 2);
            return SHWire{ halfgates_eval(a.label, b.label, table, &s->mitccrh_) };
        }
    }

private:
    friend class SH2PCSession;   // for I/O-boundary checks (ctx.s == session)
    SH2PCSession* s;
};

static_assert(BooleanContext<SH2PCContext>);

template <class T, class Clear>
inline T SH2PCSession::input(SH2PCContext& ctx, int owner, Clear clear) {
#if EMP_CONTEXT_CHECKS
    if (ctx.s != this) error("SH2PCSession::input: context is bound to a different session");
#endif
    const int W = T::width();
    std::vector<bool> e = T::encode(clear);
#ifndef NDEBUG
    if (e.size() != (size_t)W) error("SH2PCSession::input: T::encode width != T::width()");
#endif
    std::vector<block> lab(W);
    // feed_ wants a contiguous bool[]; std::vector<bool> is bit-packed, so copy.
    auto bb = std::make_unique<bool[]>(W);
    for (int i = 0; i < W; ++i) bb[i] = (i < (int)e.size()) ? (bool)e[i] : false;
    feed_(lab.data(), owner, bb.get(), (size_t)W);
    std::vector<SHWire> wires(W);
    for (int i = 0; i < W; ++i) wires[i].label = lab[i];
    return T::from_wires(ctx, wires.data());
}

template <class T>
inline auto SH2PCSession::reveal(const T& v, int recipient) {
#if EMP_CONTEXT_CHECKS
    if (!v.context() || v.context()->s != this) error("SH2PCSession::reveal: value is bound to a different session/context");
#endif
    const int W = T::width();
    std::vector<SHWire> wires(W);
    v.pack_wires(wires.data());
    std::vector<block> lab(W);
    for (int i = 0; i < W; ++i) lab[i] = wires[i].label;
    auto bb = std::make_unique<bool[]>(W);
    reveal_(bb.get(), recipient, lab.data(), (size_t)W);
    return T::decode(bb.get());
}

}  // namespace emp
#endif  // EMP_SH2PC_SESSION_H__
