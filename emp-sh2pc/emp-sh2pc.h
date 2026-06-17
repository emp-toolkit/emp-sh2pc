#ifndef EMP_SH2PC_H__
#define EMP_SH2PC_H__

// Semi-honest 2PC over the BooleanContext model. The public handle is one session,
// SH2PCSession:
//   SH2PCSession — owns ALL garbled-circuit protocol state (IO, IKNP-OT, Delta,
//                  synchronized PRG, half-gate MITCCRH/constants, COT refill
//                  buffer) and the I/O boundary: typed input<T>() / reveal<T>()
//                  plus raw-bit input_bits / reveal_bits, party(), num_and(),
//                  finalize(). sess.ctx() is the gate context values are
//                  built over. input/reveal are generic over any WireValue — the
//                  session names no value family.
//   SH2PCCtx     — the direct gate context (SH2PCSession::ctx_t). A
//                  BooleanContext whose value-return gate ops garble eagerly (AND
//                  via halfgates_garble/eval, XOR/NOT/const over labels). No global
//                  emp::backend, no Backend virtual dispatch.
// Typed circuit values (Bit_T / UInt_T / Int_T / Float_T) live in
// emp-tool/circuits/typed.h, pulled in below; build them as
// UInt_T<SH2PCSession::ctx_t, N> (etc.) over sess.ctx(). No global backend.

#include "emp-sh2pc/sh2pc_session.h"

#endif  // EMP_SH2PC_H__
