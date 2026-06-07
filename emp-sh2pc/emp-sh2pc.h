#ifndef EMP_SH2PC_H__
#define EMP_SH2PC_H__

// Semi-honest 2PC over the BooleanContext model.
//   SH2PCSession  — owns the garbled-circuit protocol state (IO, IKNP-OT, Delta,
//                   synchronized PRG, half-gate MITCCRH/constants) and typed
//                   input<T>() / reveal<T>().
//   SH2PCContext  — the value-return gate surface (a BooleanContext), no global
//                   emp::backend, no Backend virtual dispatch.
// Typed circuit values (Bit / UInt / Int / Float) live in
// emp-tool/circuits/typed.h, pulled in below. The old SemiHonestGen/Eva diamond
// and setup_semi_honest global-backend installer are gone — write circuits
// against an SH2PCContext instead.

#include "emp-sh2pc/sh2pc_session.h"

#endif  // EMP_SH2PC_H__
