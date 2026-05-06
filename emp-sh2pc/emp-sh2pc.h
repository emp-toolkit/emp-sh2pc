#ifndef EMP_SH2PC_H__
#define EMP_SH2PC_H__
#include "emp-sh2pc/semihonest.h"
#include "emp-sh2pc/sh_party.h"
#include "emp-sh2pc/sh_gen.h"
#include "emp-sh2pc/sh_eva.h"

namespace emp {
// emp-tool main split the v0.3.x variable-width signed integer type
// `Integer` into `SignedInt` (signed, runtime-width) and `UnsignedInt`
// (unsigned, runtime-width). Re-export the old name for source
// compatibility with existing emp-sh2pc users; new code should use
// SignedInt / UnsignedInt directly.
using Integer = SignedInt;
}  // namespace emp
#endif
