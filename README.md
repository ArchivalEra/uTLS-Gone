# uTLS-Gone

[![ci](https://github.com/ArchivalEra/uTLS-Gone/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ArchivalEra/uTLS-Gone/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/ArchivalEra/uTLS-Gone)](https://github.com/ArchivalEra/uTLS-Gone/releases)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![rust](https://img.shields.io/badge/rust-edition%202024-orange.svg)](Cargo.toml)
[![no Go](https://img.shields.io/badge/Go-zero%20deps-success.svg)](#the-name)
[![upstream](https://img.shields.io/badge/upstream%20fixtures-byte%20for%20byte-brightgreen.svg)](crates/utls/tests/fixtures/utls-testdata/README.md)
[![top language](https://img.shields.io/github/languages/top/ArchivalEra/uTLS-Gone)](https://github.com/ArchivalEra/uTLS-Gone)
[![last commit](https://img.shields.io/github/last-commit/ArchivalEra/uTLS-Gone)](https://github.com/ArchivalEra/uTLS-Gone/commits/main)

**A ClientHello should be a nameable, reproducible, verifiable thing — not a pile of bytes
that comes out different every time and that nobody can prove correct.**

`uTLS-Gone` is a pure-Rust port of
[`refraction-networking/utls`](https://github.com/refraction-networking/utls): given a browser
fingerprint (say, "Chrome 133"), it produces a ClientHello **identical to that browser's**, and
makes that identity **provable by re-running a single command**. On top of that, it also delivers
the biggest production consumer of the uTLS ecosystem — **a Rust equivalent of XTLS/REALITY**
(issue #1, shipped in
[`v0.1.0-reality.1`](https://github.com/ArchivalEra/uTLS-Gone/releases/tag/v0.1.0-reality.1)).

> 中文版：[README.zh.md](README.zh.md)

## The name

The repo is called `uTLS-Gone`, and `Gone` is a pun:

- **No Go**. The original uTLS is written in Go; this one is pure Rust — not a line of Go in the
  fingerprint layer or the engine layer, and none of Go's toolchain either (the one exception,
  `crates/utls/tests/fixtures/`, is **reconciliation material**: fixtures and probes produced by
  the original's own API, not a runtime dependency of this repo).
- **It runs fast**. For the same job (producing one ClientHello with real key exchanges), the
  marginal CPU cost is **about 1/8 of the original's** (13.3 µs vs 102 µs) — the measurement
  protocol, the full data, and the column that favors Go are all in the next section.

## Speed & CPU cost (measured, reproducible)

![Marginal CPU per hello: uTLS-Gone 13.3 µs vs uTLS (Go 1.27) 102 µs, 7.7×](docs/bench-en.svg)

**A comparison is only meaningful on the same layer**: ours goes through the engine seam
(`FingerprintClient::plan`: starts real key exchanges + encodes + accounts), and the matching
uTLS action is `tls.UClient(...) + BuildHandshakeState()` (`gen-reference/bench/main.go`).
Comparing the fingerprint layer's `marshal` instead yields an inflated factor (we stepped on
that one for real: it looks like 29×, but the two layers do different work).

Same machine (AMD Ryzen 9 3900X), same 39 presets (the intersection of both support sets), same
protocol: a misspelled preset name measures the bare loop; n=48 and 10n=480 runs, three reps
each, medians solve the **marginal cost**; a single-preset probe separates the **one-time
initialization**. Timing starts at the loop and excludes process startup. Reference = uTLS
master (tarball sha256 `ae5e90b0…`; fetch command in
`crates/utls/tests/fixtures/gen-reference/README.md`).

| | uTLS (Go 1.27, default build) | Ours (default release) | Ours (+ fat LTO, CGU=1) |
|---|---|---|---|
| **Marginal CPU per hello** (39-preset mean) | **102 µs** | **13.3 µs** (**7.7×**) | 13.2 µs — within noise of default |
| Single-preset `Chrome(70)` marginal | 75 µs | 11.8 µs | 9.3 µs |
| Batch mean (39 presets × 48, one-time cost amortized in) | 104.6 µs | 31.6 µs | 30.8 µs |
| First hello (cold process, unwarmed) | ~77 µs | ≈33 ms | ≈33 ms |
| First hello (after `warm_up()`) | ~77 µs (no one-time cost) | **~81 µs** | ~81 µs |
| **Allocated bytes per hello** (39-preset mean, cumulative heap allocs in the loop) | **20.8 KB** | **9.7 KB** (reused planner) / 10.8 KB (per-connection) | same (LTO does not change allocation behavior) |
| Peak RSS (empty run = 18,720 hellos) | ~16 MB, flat | ~16 MB, flat | ~16 MB, flat |

Written in full, including the rows that favor the other side:

- **The first-hello ~33 ms: root cause pinned, fix shipped and measured**. The cost is aws-lc's
  first in-process `RAND_bytes` running its jitter-entropy collection — pure userspace
  (`strace -c`: all syscalls of the entire process total 0.4 ms), the second fill takes
  **~330 ns**, and keygen-first pays it too (keygen goes through RAND). Known upstream as
  [aws-lc-rs#1140](https://github.com/aws/aws-lc-rs/issues/1140) (open), and `aws_lc_rs::init()`
  is a no-op. The engine ships an explicit warm-up, **`utls_engine::warm_up(&provider)`** (a
  single 32-byte RNG fill): one line at server startup takes the first hello from
  **≈33 ms to ~81 µs** — same ballpark as Go's cold first hello (~77 µs). The table keeps the
  unwarmed ≈33 ms because **a cold process that never calls `warm_up()` really does pay it**;
  the benchmark measures cold by default, warmed numbers via `PLANCOST_WARM=1`. TLS 1.2-era
  presets never touch the provider RNG: ~50 µs each, never affected.
- **Memory**: peak RSS is a tie — **~16 MB on both sides**, and the empty run equals the
  18,720-hello run exactly (allocator/GC reuse everything; neither grows with the count).
  The difference is **allocation volume per hello**: Go **20.8 KB** vs ours **9.7 KB** (reused
  planner) / 10.8 KB (`PLANCOST_FRESH=1`, a fresh planner per hello — matching uTLS's real
  one-UClient-per-connection shape), about **2.1×**. Metric: cumulative heap allocations
  inside the loop — Go `TotalAlloc` ↔ Rust counting allocator (realloc counted at the new
  size); `plan-cost` prints an `alloc_bytes=` line.
- **LTO was measured and changes nothing** (fat LTO + codegen-units=1: marginal 13.3 → 13.2 µs,
  within noise): the hot spots are the crypto primitives (aws-lc-rs assembly, with runtime
  instruction dispatch) and the runtime init — **not inlining opportunities**. PGO was not
  measured — by the same shape, its headroom is limited; we don't claim otherwise.
- **Model check**: 39 presets × 480 runs each (18,720 units per process) measured Go 1.9185 s /
  ours 283.6 ms; the linear model (one-time + marginal × count) predicts 1919 / 283.6 ms — it
  holds.
- The benchmarks themselves:
  [`crates/utls-engine/examples/plan-cost.rs`](crates/utls-engine/examples/plan-cost.rs) (prints
  `checksum=`: FNV-1a over all output bytes, so "fast because it did nothing" is impossible) and
  [`crates/utls/tests/fixtures/gen-reference/bench/main.go`](crates/utls/tests/fixtures/gen-reference/bench/main.go).

## Why a fork is mandatory

"You could do this on upstream rustls with just an extension list" — **retracted**; that
sentence is wrong. Two hard constraints:

1. rustls **has no** public API for customizing the ClientHello. `ClientConfig` has no extension
   table, no ordering, no GREASE; `ClientConfig::dangerous()` exposes only a
   `set_certificate_verifier`. The maintainers have closed this request explicitly, more than
   once.
2. Since rustls 0.23.0, it **shuffles extension order per connection**. That means: even with a
   perfectly correct cipher-suite and extension set, upstream cannot produce a stable
   fingerprint.

So this project has the same shape as uTLS: **fork the TLS engine, put a fingerprint layer on
top of it**. The only difference is the engine — rustls instead of Go's `crypto/tls`. This is
not a choice one could route around; it is the premise.

## Existing work, and what it lacks

"There is no uTLS alternative in the Rust ecosystem" — **retracted**; that sentence is wrong too.
The routes that actually exist:

| Project | Status | Gap |
|---|---|---|
| `3andne/craftls` | a rustls 0.22 fork with `FingerprintBuilder`; the one rustls maintainers themselves recommended in an issue | stuck on an old rustls, unmaintained |
| `apify/rustls` | the only fork still tracking upstream, at 0.23.4x | built for someone else's project; the interface serves its owner |
| `XOR-op/rustls.delta` + `ja-tools` | minimal delta — measured, a few files and a dozen lines per version | tracks one old version; mounts via `[patch.crates-io]`, can't reach crates.io |

Together they prove one thing: **this road works in Rust, and the patch can be small** — but
nobody has turned it into a complete uTLS with a preset table. That is the gap this project
fills.

## Architecture

Two edges, one-directional:

```
       utls layer (ours)                    rustls (vendored fork)
  ┌────────────────────────────┐        ┌──────────────────────────────┐
  │ ClientHello data model      │        │  handshake state machine     │
  │ serialize / GREASE / pad    │ ─────▶ │  · instrumented at CH build  │
  │ preset table (fingerprints) │        │  · per-conn shuffle suppressed │
  │ parse fingerprints from raw │ ◀───── │  · may advertise suites it    │
  └────────────────────────────┘        │    cannot itself negotiate    │
                                        └──────────────────────────────┘
```

| crate | what it is |
|---|---|
| `utls` | the fingerprint layer: ClientHello data model, serialization / GREASE / padding, preset table, parsing fingerprints back from raw bytes |
| `utls-engine` | the seam between fingerprint layer and engine: planning the externally-provided hello, key exchanges, session resumption, ECH proposals |
| `rustls` | vendored rustls 0.23.45, 9 files marked `FORK(utls-rs)`; the patch and its criteria live in `crates/rustls-fork/` |
| `reality` | the Rust equivalent of REALITY (issue #1, next section) |

**The fingerprint layer references no rustls types.** The reason is empirical: rustls has
reworked its internal extension representation twice in two years. Keeping the volatile part
inside a thin adapter is what reduces the cost of following upstream from "rewrite" to
"re-align the lines".

## REALITY (issue #1, shipped in v0.1.0-reality.1)

This repo's first issue asked for a Rust equivalent of REALITY with
[`XTLS/REALITY`](https://github.com/XTLS/REALITY) as the **authoritative reference** (no
second-hand ports). It lives in `crates/reality/`, with **all 36 criteria green** (including
two stock-Xray true-stack tests), covering:

- **Auth & KDF**: AuthKey = X25519(server static priv, client ephemeral pub) → HKDF-SHA256;
  `sessionId` sealing = AES-256-GCM with the AAD being **the entire ClientHello with the
  sessionId zeroed**. KDF and sealing are byte-for-byte cross-checked **in both directions**
  against vectors produced by the Go reference implementation.
- **Fallback decision**: the server-side decision logic from upstream `tls.go:213-275`, ported
  whole — 10 criteria.
- **Mirror handshake**: a half TLS 1.3 server handshake run by us — the real site's ServerHello
  is the template and only the key bytes change; EE / Certificate / CertificateVerify /
  Finished are all produced here. Mirrorable groups: `X25519(29)`, `X25519MLKEM768(4588)`, and
  the three NIST groups `P-256` / `P-384` / `P-521` (issue #3; P-521 additionally needs a
  provider that implements it — the bundled aws-lc backend doesn't, so those connections fall
  back to passthrough). P-256 matters because putting it in the `key_share` is how a client
  avoids an HRR from origins that only accept P-256. The old two-group ceiling was uTLS's own
  key-share capability; this repo's client half is injective (caller-held keys), so a P-256
  selection is completable here — and a true-stack criterion proves it end to end.
- **Client half**: can initiate a REALITY connection on top of the rustls fork — fingerprint
  hello, caller-held X25519 for the auth key, provider-held exchanges for the rest, and the
  mirror certificate recognized by its HMAC tail. Proven end-to-end against our own server with
  a P-256-only origin (bidirectional roundtrip).
- **Config parity**: all 21 fields of Xray's `config.proto`, reconciled field by field,
  bidirectional, and provably red.
- **True stack (stock Xray-core 26.3.27)**: an authenticated client succeeds and carries
  traffic; an unauthenticated hello is forwarded to the real site and receives the byte-for-byte
  identical certificate chain of a direct connection.

The protocol shape, the measured findings, and the known boundaries (ML-DSA-65 not implemented;
HRR not handled — the reference doesn't either) are documented where the code lives
(`crates/reality/src/server.rs`, `crates/reality/src/mirror_tls.rs`).
## Where it stands

- **Fingerprint layer**: preset table, GREASE, padding, extension shuffling, randomized family,
  structured extension sets, parsing fingerprints from raw bytes. Byte-for-byte identical to the
  original's `testdata/` fixtures.
- **Engine layer**: vendored rustls + **eight instrumentation points** (externally-provided
  ClientHello, shuffle suppression, advertising suites it can't negotiate, dropping the
  unconditionally-appended SCSV, external key exchange, external second flight, session
  resumption, real ECH proposals) — the provenance of each and why upstream refuses to do them
  are in `crates/rustls-fork/README.md`.
- **REALITY**: previous section — 36 criteria green, including the stock-Xray true stack.
- **The accepting half of real ECH works**: Cloudflare, defo.ie, and test.defo.ie all accept;
  plus an **offline** criterion (our client ↔ uTLS's own ECH server).
- **40 of the 41 presets go through the engine path** (`cargo run --release --example plan-cost`
  prints the list). The one refusal is `HelloCustom` = an empty spec, rejected for "no cipher
  suites" — an empty spec is not a legal ClientHello; that is not a debt.
- Two shapes that once "couldn't go out on the wire", now handled, with their boundaries:
  - **TLS 1.2-era old presets** (Chrome 58/62, Firefox 55/56, Ios 11/12, Android 11): the spec
    has no `key_share`, so they can only do TLS 1.2 — the engine now produces exactly that
    shape, and truly negotiates `TLSv1_2` against a server offering both 1.2/1.3. **The
    caller's config must also enable only 1.2**: otherwise the downgrade sentinel the server
    puts into the ServerHello random is judged as a downgrade attack (same for Go/uTLS).
  - **PQ presets** (ChromePq 115/120, ChromePsk 115): `X25519Kyber768Draft00` in the
    `key_share` is a draft group the rustls provider doesn't have. The engine sends a
    **correctly-sized placeholder public key** for that group (shape identical to Chrome's,
    total length matching the ledger), while the real exchange only offers the X25519 it can
    complete ⇒ if the server doesn't know the draft group it negotiates as usual; if it **does
    know it and selects it**, the failure is loud (never a silent group swap).
- **Every key-exchange group the engine can emit has a positive criterion** (the server filters
  `kx_groups` down to just that group, so "the handshake succeeded" itself proves "it was
  used"): three for P-256 in
  [`tests/p256_handshake.rs`](crates/utls-engine/tests/p256_handshake.rs), three for the hybrid
  group `X25519MLKEM768(4588)` in
  [`tests/mixed_group_handshake.rs`](crates/utls-engine/tests/mixed_group_handshake.rs). Both
  situations covered: selected in the first flight, only share in the `key_share`, and HRR when
  the server insists — the second flight carries a **fresh** share (1216 bytes for the hybrid
  group) with the client random byte-for-byte unchanged.
- ⚠️ **`Browser360(7)` cannot negotiate**, and the reason is the **cipher suites**, not the
  engine: its 20 suites are all CBC/RC4/3DES, and a modern TLS stack (rustls implements exactly
  6 TLS 1.2 suites: AES-GCM and CHACHA20) intersects it in **zero** suites — Go under uTLS
  doesn't implement them by default either. Its bytes stay faithful; the peer just has to be a
  server that still knows the old suites.

## What's left for parity

For every test family in `uTLS`: how far our verdict reaches, which gaps are real, which belong
to rustls's territory (not rewritten), and which the upstream itself never tested — one
checkable table in [`docs/utls-parity.md`](docs/utls-parity.md).
**"Fully equivalent" is not a sentence; it is that table.**

## Criteria & CI

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs six groups of criteria, each
able to go red on its own:

| job | what it judges |
|---|---|
| `rust` | `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-features` |
| `patch-repro` | apply `patch.diff` onto **pristine** rustls 0.23.45; the result must match `crates/rustls` **file by file** (`crates/rustls-fork/verify-patch.sh`) |
| `ech-offline` | inner hello byte-for-byte identical to uTLS's; our client passes uTLS's own ECH server |
| `upstream` | the original `refraction-networking/utls` test suite (the two network-bound ones `-skip`) |
| `upstream-no-skip` | same, but **nothing skipped** — those two target domains are swapped at build time via `go -overlay` to directly reachable ones (the upstream tree on disk untouched) |
| `reality-stack` | the stock-Xray true stack: authentication succeeds and carries traffic; the fallback matches a direct connection byte for byte |

**Not run in CI, and why** (not forgotten):

- **Networked criteria** (`end_to_end`, `ech_e2e`): they hit browserleaks / Cloudflare /
  defo.ie on 443. Locally: `cargo test -p utls-engine --test end_to_end -- --ignored`
  (likewise `ech_e2e`).
- **Benchmark** `plan-cost`: prints numbers for humans, not a gate (another machine, other
  numbers).

**The two original tests that need the real internet** (`TestVerifyHostname` /
`TestRealResumption`) have two routes; the two `ci.yml` jobs take one each, and **neither is
"skipping"**:

- `upstream` — the upstream tree stays **unmodified by a single byte**; the price is `-skip` on
  those two;
- `upstream-no-skip` — **nothing skipped**; the price is that the two dial targets change from
  `www.google.com` / `yahoo.com` to the directly reachable, criteria-equivalent
  `www.baidu.com` (via `go -overlay` replacing the test files **at build time**; the upstream
  tree on disk still untouched). The mechanisms these two tests exercise (hostname verification
  / real TLS 1.3 resumption) are peer-independent; swapping the domain touches no assertion —
  but it is **another** criterion, not a substitute for the unmodified one.
  One command locally: `sh crates/utls/tests/fixtures/gen-reference/run-upstream-suite.sh <tree>`
  ⇒ top level **222 PASS / 0 FAIL / 1 SKIP** (the only skip is upstream's own `t.Skip`).

## Run it

```bash
cargo test --workspace --all-features    # every offline criterion (REALITY's 36 among them)
cargo clippy --workspace --all-targets --all-features

# REALITY true stack (needs stock Xray; see xray_bin() in tests/real_stack.rs, REALITY_XRAY overrides)
cargo test -p reality --test real_stack -- --include-ignored

# networked criteria (#[ignore] by default)
cargo test -p utls-engine --test end_to_end -- --ignored
cargo test -p utls-engine --test ech_e2e -- --ignored

# offline ECH criteria (needs Go and a uTLS source tree; fetch command in
# crates/utls/tests/fixtures/gen-reference/README.md)
cargo test -p utls-engine --test ech_inner_utls
cargo test -p utls-engine --test ech_utls_server -- --ignored

# the original suite, **no -skip and no proxy** (same tree) ⇒ 222 PASS / 0 FAIL / 1 SKIP
sh crates/utls/tests/fixtures/gen-reference/run-upstream-suite.sh /tmp/utls-ref/utls-master

```

## Explicit non-goals

HTTP/2 fingerprinting — uTLS doesn't have it either; it belongs to another layer (the
`ClientProfile`-style wrappers). This project does **ClientHello** only (TLS over TCP).

⚠️ **HTTP/3 needs to be discussed separately — don't copy the old wording**: upstream uTLS
**does have** a QUIC fingerprint layer (`u_quic.go` / `u_quic_transport_parameters.go`, written
by them, with golden-bytes and GREASE-version tests) — this file used to say "uTLS itself has no
HTTP/3 fingerprint", and that sentence was wrong. The **transport-parameters encoding layer**
is now ported (`crates/utls/src/quic.rs`; the Firefox parameter set matches the upstream golden
bytes byte for byte, with the same GREASE-version-distribution / sentinel-replacement criteria);
what's not wired yet is the `UQUICConn` connection seam (rustls has `pub mod quic`). Per-item
status in [`docs/utls-parity.md`](docs/utls-parity.md).

## License

**Our own code**: **Apache-2.0** (full text in `LICENSE`, taken from
<https://www.apache.org/licenses/LICENSE-2.0.txt>; SPDX in the `license` field of `Cargo.toml`).

A permissive license with an **explicit patent grant** (§3): anyone may use it commercially,
keep their source closed, modify and redistribute — provided the copyright and license notices
are kept and changes are stated in modified files. For protocol implementations, Apache over
MIT is mainly about that patent grant.

When **non-commercial use must be enforced** (this repo currently allows it), the alternative is
a one-place change: `PolyForm Noncommercial 1.0.0` (permanently non-commercial) or `BSL 1.1`
(non-commercial until the change date, then permissive).

Two pieces of **code we did not write** live in this repo; their licenses and provenance are in
`THIRD-PARTY.md`:

- `crates/rustls/` — vendored **rustls 0.23.45** (Apache-2.0 / ISC / MIT, texts included with
  the copy in `crates/rustls/LICENSE-*`), 9 files marked `FORK(utls-rs)`, patch in
  `crates/rustls-fork/`;
- **fixtures and tables** derived from **`refraction-networking/utls`** (BSD-3-Clause):
  `tests/fixtures/utls-testdata/`, `utls-reference.json` / `utls-randomized.json`, and the
  transcribed preset/weight tables. They are here because this repo's criterion is
  "byte-for-byte identical to the reference implementation" — the criteria must carry the
  upstream's original bytes.
