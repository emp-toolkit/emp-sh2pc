#ifndef EMP_SH2PC_SESSION_H__
#define EMP_SH2PC_SESSION_H__

// SH2PCSession — the public handle for semi-honest 2PC (garbled circuits), the
// SH2PC peer of ClearSession. It owns ALL protocol state — IO, IKNP-OT, Delta, the
// synchronized PRG, the half-gate MITCCRH/constants, and the COT refill buffer —
// and the I/O boundary (input / reveal); sess.direct_ctx() is the gate context values are
// built over. Gates are eager (an AND garbles/evaluates as it is called), so there
// is no chunk/checkpoint model: a value's wire IS the live garbled label.
//
//   SH2PCSession sess(io, party);
//   using Ctx = SH2PCSession::DirectCtx; using UInt32 = UInt_T<Ctx, 32>;
//   auto a = sess.input<UInt32>(ALICE, x);
//   auto b = sess.input<UInt32>(BOB,   y);
//   auto c = a + b;                          // eager half-gate over sess.direct_ctx()
//   auto out = sess.reveal(c, PUBLIC);       // open the result
//
// Public constants stay value/context-level: UInt32::constant(sess.direct_ctx(), 7).
// There is no global backend and no virtual dispatch — the session is explicit.

#include "emp-sh2pc/sh2pc_ctx.h"                 // SH2PCCtx (Wire = block)
#include "emp-tool/emp-tool.h"
#include "emp-tool/ir/context/context.h"
#include "emp-tool/circuits/typed.h"             // Bit_T / UInt_T / Int_T / Float_T / BitVec_T
#include "emp-tool/circuits/value_traits.h"      // value_traits<T>: width/encode/decode
#include "emp-tool/ir/session/session_io.h"            // Session / DirectSession / SessionIO
#include "emp-tool/runtime/crypto/mitccrh.h"
#include "emp-ot/emp-ot.h"
#include <cstring>
#include <memory>
#include <optional>
#include <type_traits>
#include <vector>

namespace emp {

class SH2PCSession {
public:
    using DirectCtx = SH2PCCtx;   // the direct/user gate context; values are UInt_T<DirectCtx,N> etc.
    // reveal returns std::optional<clear_t> (the session contract): the value is
    // present only on a party that learns it — every party for PUBLIC, the named
    // recipient for ALICE/BOB, both parties (each its own share) for an XOR reveal —
    // and std::nullopt on a party that does not learn it.
    template <class V> using reveal_t = std::optional<typename V::clear_t>;

    SH2PCSession(IOChannel* io, int party, int batch_sz = 1024 * 16)
        : party_(party), io_(io), batch_size_(batch_sz) {
        if (party_ != ALICE && party_ != BOB)
            error("SH2PCSession: party must be ALICE or BOB");
        if (io_ == nullptr) error("SH2PCSession: io channel must not be null");
        if (batch_size_ <= 0) error("SH2PCSession: batch size must be positive");
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
        ctx_.bind_(party_, io_, delta_, constant_, &mitccrh_);
    }
    SH2PCSession(const SH2PCSession&) = delete;
    SH2PCSession& operator=(const SH2PCSession&) = delete;

    void finalize() {}

    // The direct gate context, for value construction that is not I/O — e.g. public
    // constants UInt_T<DirectCtx,32>::constant(sess.direct_ctx(), 7), operators, or
    // frontend::run.
    DirectCtx& direct_ctx() { return ctx_; }

    int party() const { return party_; }
    // AND-gate count so far (mitccrh advances gid by 2 per garbled AND).
    uint64_t num_and() const { return mitccrh_.gid / 2; }

    // ---- typed I/O (the only way clear values enter / leave a circuit) ----
    // input<V>(owner, clear): V is any WireValue over THIS session's DirectCtx, e.g.
    // UInt_T<DirectCtx,32>. Called by both parties; only `owner`'s clear is used.
    template <WireValue V>
    V input(int owner, const typename V::clear_t& clear) {
        static_assert(std::same_as<typename V::context_type, DirectCtx>,
            "SH2PCSession::input<V>: V must be a value over this session's DirectCtx");
        const int W = value_traits<V>::width();
        std::vector<bool> e = value_traits<V>::encode(clear);
        // Always enforced (not debug-only): a short/long encoding is a codec bug;
        // never silently pad — wrong input bits would corrupt the result.
        if (e.size() != (size_t)W) error("SH2PCSession::input: V::encode width != V::width()");
        // feed_ wants a contiguous bool[]; std::vector<bool> is bit-packed, so copy.
        auto bb = std::make_unique<bool[]>(W);
        for (int i = 0; i < W; ++i) bb[i] = (bool)e[i];
        std::vector<block> wires(W);
        feed_(wires.data(), owner, bb.get(), (size_t)W);
        return V::from_wires(ctx_, wires.data());
    }

    // reveal<V>(v, recipient): open to recipient (ALICE/BOB/PUBLIC/XOR-share),
    // returning std::optional<clear_t>. The protocol exchange runs on both parties;
    // the value is then present only on a party that learns it — every party for
    // PUBLIC, the named recipient for ALICE/BOB, and both parties (each its own
    // secret-share, whose XOR is the cleartext) for an XOR reveal. A party that does
    // not learn it gets std::nullopt rather than a decoded placeholder.
    template <WireValue V>
    reveal_t<V> reveal(const V& v, int recipient) {
        static_assert(std::same_as<typename V::context_type, DirectCtx>,
            "SH2PCSession::reveal<V>: V must be a value over this session's DirectCtx");
#if EMP_CONTEXT_CHECKS
        if (v.context() != &ctx_) error("SH2PCSession::reveal: value is bound to a different context");
#endif
        const int W = value_traits<V>::width();
        std::vector<block> wires(W);
        v.pack_wires(wires.data());
        auto bb = std::make_unique<bool[]>(W);
        reveal_(bb.get(), recipient, wires.data(), (size_t)W);
        if (recipient == PUBLIC || recipient == XOR || recipient == party_)
            return std::optional<typename V::clear_t>(value_traits<V>::decode(bb.get()));
        return std::nullopt;
    }

    // ---- raw-bit I/O: width-agnostic, for values past the 64-bit clear codec
    // (e.g. 128-bit AES blocks) or hand-assembled wire vectors. ----
    std::vector<block> input_bits(int owner, const bool* in, size_t n) {
        std::vector<block> r(n);
        feed_(r.data(), owner, in, n);
        return r;
    }
    void reveal_bits(bool* out, int recipient, const block* w, size_t n) {
        reveal_(out, recipient, w, n);
    }

private:
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
    SH2PCCtx ctx_;                        // the gate context, bound after handshake

    void refill_() {
        ot_->rcot(buf_.get(), batch_size_);
        if (party_ == BOB)
            for (int i = 0; i < batch_size_; ++i) buff_[i] = getLSB(buf_[i]);
        top_ = 0;
    }

    // feed `length` input bits owned by `from_party` into `label` (block labels).
    // PUBLIC is a public constant (both parties build the same constant labels, no
    // OT — neither party's value can override it); ALICE/BOB are private inputs.
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

    void reveal_(bool* out, int to_party, const block* label, size_t length) {
        if (to_party != XOR && to_party != ALICE && to_party != BOB && to_party != PUBLIC)
            error("SH2PCSession::reveal: recipient must be ALICE, BOB, PUBLIC, or XOR");
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

static_assert(Session<SH2PCSession>);
static_assert(DirectSession<SH2PCSession>);
static_assert(SessionIO<SH2PCSession, UInt_T<SH2PCSession::DirectCtx, 32>>);

}  // namespace emp
#endif  // EMP_SH2PC_SESSION_H__
