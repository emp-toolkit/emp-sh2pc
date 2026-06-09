#ifndef EMP_SH2PC_H__
#define EMP_SH2PC_H__

// Semi-honest 2PC over the BooleanContext model. The public handle is one session,
// SH2PCSession:
//   SH2PCSession — owns ALL garbled-circuit protocol state (IO, IKNP-OT, Delta,
//                  synchronized PRG, half-gate MITCCRH/constants, COT refill
//                  buffer) and the I/O boundary: typed input<T>() / reveal<T>()
//                  plus raw-bit input_bits / reveal_bits, party(), num_and(),
//                  finalize(). sess.ctx() is the gate context values are built over.
//   SH2PCCtx     — the gate context (SH2PCSession::Ctx). A BooleanContext whose
//                  value-return gate ops garble eagerly (AND via halfgates_garble/
//                  eval, XOR/NOT/const over labels). No global emp::backend, no
//                  Backend virtual dispatch.
// Typed circuit values (Bit_T / UInt_T / Int_T / Float_T) live in
// emp-tool/circuits/typed.h, pulled in below; build them as SH2PCSession::UInt<N>
// (etc.) over sess.ctx(). There is no global backend.

#include "emp-sh2pc/sh2pc_session.h"

#endif  // EMP_SH2PC_H__
