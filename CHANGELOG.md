# Changelog

Notable changes to emp-sh2pc. Versions are the git tags. CMake package
metadata is numeric (see the README's version guidance).

## v1.0.0-alpha.2

First tagged alpha of the 1.0 development line, numbered to match the
emp-tool and emp-ot `v1.0.0-alpha.2` it pairs with and requires. The 0.3.x
line (tag `0.3.0`, branch `v0.3.x`) is maintained separately and receives
backported fixes.

### Stability

- Pre-1.0 API: headers and names may change between alpha tags and before
  the final `1.0.0`. Pin to a tag, and pin the paired emp-tool and emp-ot
  tags.

### Contents

- `SH2PCSession`: semi-honest two-party computation by garbled circuits
  (half-gates) over one `IOChannel`. Values are emp-tool's context-bound
  types (`Bit_T`, `UInt_T`, `Int_T`, `Float_T`, `BitVec_T`) over the session's
  `ctx_t`; `input` and `reveal` are generic over any `WireValue`, and
  `reveal` returns a `std::optional` that is empty on a party that does not
  learn the value. There is no global backend: 0.3.x's `setup_semi_honest`
  and its global `Integer` / `Bit` are gone.
- `SH2PCSessionT<OTExt>` takes any emp-ot OT extension (`IKNP`, the default,
  `SoftSpoken<k>`, `Ferret`) for the correlated OTs behind the evaluator's
  input bits; `SH2PCSession` is `SH2PCSessionT<IKNP>`.
- `num_and()` reports the exact number of AND gates garbled or evaluated.
