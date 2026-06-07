#ifndef EMP_SH2PC_H__
#define EMP_SH2PC_H__

// Semi-honest 2PC over the BooleanContext model.
//   SH2PCCtx — the SINGLE user-facing handle. It owns ALL garbled-circuit
//              protocol state (IO, IKNP-OT, Delta, synchronized PRG, half-gate
//              MITCCRH/constants, COT refill buffer), IS a BooleanContext (the
//              value-return gate surface: AND via halfgates_garble/eval, XOR/NOT/
//              const over labels; no global emp::backend, no Backend virtual
//              dispatch), and exposes typed input<T>() / reveal<T>() plus raw-bit
//              input_bits / reveal_bits, party(), num_and(), finalize().
// Typed circuit values (Bit_T / UInt_T / Int_T / Float_T) live in
// emp-tool/circuits/typed.h, pulled in below. Write circuits against an SH2PCCtx;
// it is the one semi-honest 2PC context and uses no global backend.

#include "emp-sh2pc/sh2pc_session.h"

#endif  // EMP_SH2PC_H__
