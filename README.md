# emp-sh2pc
![build](https://github.com/emp-toolkit/emp-sh2pc/workflows/build/badge.svg)
[![CodeQL](https://github.com/emp-toolkit/emp-sh2pc/actions/workflows/codeql.yml/badge.svg)](https://github.com/emp-toolkit/emp-sh2pc/actions/workflows/codeql.yml)

<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/art/logo-full.jpg" width=300px/>

> **Which version do I want?**
>
> - **Existing projects pinned to a published release: stay on `0.3.0`** —
>   branch [`v0.3.x`](https://github.com/emp-toolkit/emp-sh2pc/tree/v0.3.x).
>   Bug fixes and security patches will be backported to `v0.3.x`.
> - **New projects, or able to track a moving API: use the development branch**
>   (this branch, `main`). It will become `1.0.0-alpha` after a polish
>   pass and then `1.0.0`. Builds against emp-tool / emp-ot ≥ 1.0
>   (unified `Backend` execution layer, de-templated IO and OT) — but
>   the API is not yet frozen and headers may move between alphas.
>   Requires emp-tool ≥ 1.0.0-alpha and emp-ot ≥ 1.0.0-alpha.

Header-only semi-honest 2PC built on top of [emp-tool](https://github.com/emp-toolkit/emp-tool) and [emp-ot](https://github.com/emp-toolkit/emp-ot): garbled-circuit evaluation (half-gates) for `Bit` / `Integer` / `Float` over a `NetIO` channel, with batched IKNP COT for input wires.

## Usage

The public handle is one session, `SH2PCSession`: it owns the IO channel and all
protocol state, and `sess.ctx()` is the gate context your values are built over.

```cpp
#include <emp-sh2pc/emp-sh2pc.h>
using namespace emp;

NetIO io(party == ALICE ? nullptr : "127.0.0.1", port);
SH2PCSession sess(&io, party);

using UInt32 = SH2PCSession::UInt<32>;
auto a = sess.input<UInt32>(ALICE, av);   // each party owns its input
auto b = sess.input<UInt32>(BOB,   bv);
auto c = a + b;                            // eager half-gate over sess.ctx()
uint32_t out = sess.reveal(c, PUBLIC).value();  // open the result to both parties
```

`reveal` returns `std::optional<clear_t>`: the value on a party that learns it —
every party for `PUBLIC`, the named recipient for `reveal(v, ALICE)` / `reveal(v, BOB)`,
both parties (each its own secret-share) for `reveal(v, XOR)` — and `std::nullopt`
on a party that does not. Circuit values are emp-tool's context-bound types:
`SH2PCSession::Bit`, `UInt<N>`, `Int<N>`, `Float<W>`, `BitVec<N>`. Public constants
use `UInt32::constant(sess.ctx(), 1)`.
A reusable circuit is compiled once with the emp-tool frontend and replayed over the
session's context with `frontend::run(sess.ctx(), circuit, args...)`. There is no
global backend — the session is explicit.

## Requirements

- CMake ≥ 3.21
- A C++20 compiler (Clang ≥ 14, GCC ≥ 10, AppleClang 14+)
- [emp-tool](https://github.com/emp-toolkit/emp-tool) ≥ 1.0
- [emp-ot](https://github.com/emp-toolkit/emp-ot) ≥ 1.0
- pthreads

emp-sh2pc is header-only; the build produces test executables only.

## Build and install

emp-sh2pc consumes emp-tool and emp-ot through their installed CMake
packages. Install both first, then build emp-sh2pc the same way:

```bash
# emp-tool
git clone https://github.com/emp-toolkit/emp-tool.git
cmake -S emp-tool -B emp-tool/build -DCMAKE_BUILD_TYPE=Release
cmake --build emp-tool/build -j
cmake --install emp-tool/build       # respects CMAKE_INSTALL_PREFIX

# emp-ot
git clone https://github.com/emp-toolkit/emp-ot.git
cmake -S emp-ot -B emp-ot/build -DCMAKE_BUILD_TYPE=Release
cmake --build emp-ot/build -j
cmake --install emp-ot/build

# emp-sh2pc
git clone https://github.com/emp-toolkit/emp-sh2pc.git
cmake -S emp-sh2pc -B emp-sh2pc/build -DCMAKE_BUILD_TYPE=Release
cmake --build emp-sh2pc/build -j
cmake --install emp-sh2pc/build
```

If you don't want to install the dependencies, point emp-sh2pc directly
at sibling build trees:

```bash
cmake -S emp-sh2pc -B emp-sh2pc/build \
      -DCMAKE_BUILD_TYPE=Release \
      -Demp-tool_DIR=$PWD/emp-tool/build \
      -Demp-ot_DIR=$PWD/emp-ot/build
cmake --build emp-sh2pc/build -j
```

## Test

Tests live under `test/` and ship as executables in `build/`. Both
parties run on `localhost` for local testing, joined by the `./run`
wrapper script.

* Local machine, both parties on `localhost`:

  `./run ./build/[binary] [more opts]`

  e.g. `./run ./build/test_bit` or
       `./run ./build/test_example 123`.

* Two machines (IP addresses hardcoded in the test source):

  `./build/[binary] 1 12345 [more opts]` on one machine and
  `./build/[binary] 2 12345 [more opts]` on the other.

* `test_example` takes a per-party integer; the two parties must use
  different numbers:

  `./build/test_example 1 12345 123 & ./build/test_example 2 12345 124`

`ctest --test-dir build --output-on-failure` runs the entire suite.

## Library use

Downstream CMake projects link against the `emp-sh2pc::emp-sh2pc`
INTERFACE target, which transitively brings in
`emp-ot::emp-ot` and `emp-tool::emp-tool`:

```cmake
find_package(emp-sh2pc 1.0 REQUIRED)
target_link_libraries(my-app PRIVATE emp-sh2pc::emp-sh2pc)
```

## Question
Please send email to wangxiao@cs.northwestern.edu

## Acknowledgement
This work was supported in part by the National Science Foundation under Awards #1111599 and #1563722.

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
