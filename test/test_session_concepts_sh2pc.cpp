// Compile-time gate: SH2PCSession models the emp-tool session concepts and its
// gate context is a pure BooleanContext. No network — the test IS that this
// translation unit compiles; main() only confirms the binary links and runs.
#include "emp-sh2pc/emp-sh2pc.h"
#include "emp-tool/ir/session/session_io.h"
#include <cstdio>
#include <optional>
#include <type_traits>
using namespace emp;

static_assert(Session<SH2PCSession>);
static_assert(DirectSession<SH2PCSession>);
static_assert(SessionIO<SH2PCSession, UInt_T<SH2PCSession::ctx_t, 32>>);
static_assert(SessionIO<SH2PCSession, Int_T<SH2PCSession::ctx_t, 32>>);
static_assert(SessionIO<SH2PCSession, BitVec_T<SH2PCSession::ctx_t, 128>>);

// ctx_t is the direct gate context; the value layer is built over it.
static_assert(std::is_same_v<SH2PCSession::ctx_t, SH2PCCtx>);
static_assert(BooleanContext<SH2PCCtx>);
static_assert(std::is_same_v<UInt_T<SH2PCSession::ctx_t, 32>, UInt_T<SH2PCCtx, 32>>);

// reveal returns std::optional<clear_t> (nullopt on a party that does not learn it).
static_assert(std::is_same_v<
    SH2PCSession::reveal_t<UInt_T<SH2PCSession::ctx_t, 32>>,
    std::optional<UInt_T<SH2PCSession::ctx_t, 32>::clear_t>>);

int main() {
    std::printf("test_session_concepts_sh2pc: PASS\n");
    return 0;
}
