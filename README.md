# uTLS-Gone

[![ci](https://github.com/ArchivalEra/uTLS-Gone/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ArchivalEra/uTLS-Gone/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/ArchivalEra/uTLS-Gone)](https://github.com/ArchivalEra/uTLS-Gone/releases)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![rust](https://img.shields.io/badge/rust-edition%202024-orange.svg)](Cargo.toml)
[![no Go](https://img.shields.io/badge/Go-zero%20deps-success.svg)](#utls-gone)
[![top language](https://img.shields.io/github/languages/top/ArchivalEra/uTLS-Gone)](https://github.com/ArchivalEra/uTLS-Gone)
[![last commit](https://img.shields.io/github/last-commit/ArchivalEra/uTLS-Gone)](https://github.com/ArchivalEra/uTLS-Gone/commits/main)

**ClientHello 应该是可命名、可复现、可验证的东西 —— 而不是一段每次都不一样、
没人能证明它对的字节。**
**A ClientHello should be a nameable, reproducible, verifiable thing — not a pile of bytes
that comes out different every time and that nobody can prove correct.**

`uTLS-Gone` 是 [`refraction-networking/utls`](https://github.com/refraction-networking/utls)
的纯 Rust 复刻，并附带 **XTLS/REALITY 的 Rust 等价实现**（issue #1，随
[`v0.1.0-reality.1`](https://github.com/ArchivalEra/uTLS-Gone/releases/tag/v0.1.0-reality.1) 发布）。
`uTLS-Gone` is a pure-Rust port of
[`refraction-networking/utls`](https://github.com/refraction-networking/utls), plus **a Rust
equivalent of XTLS/REALITY** (issue #1, shipped in
[`v0.1.0-reality.1`](https://github.com/ArchivalEra/uTLS-Gone/releases/tag/v0.1.0-reality.1)).

## 文档 / Documentation

| 语言 / Language | |
|---|---|
| **简体中文** | [README.zh.md](README.zh.md) |
| **English** | [README.en.md](README.en.md) |

两份内容同构：名字的由来、为什么必须 fork、架构、速度与 CPU 消耗的实测对比、REALITY 交付、
事实系统、判据与 CI、跑法、非目标与 License。
Both files are structural mirrors: the name, why a fork is mandatory, the architecture, the
measured speed & CPU comparison, the REALITY delivery, the fact system, criteria & CI, how to
run it, non-goals, and the license.

- 纯 Rust，零 Go 依赖；ClientHello 与原版 `testdata/` 夹具逐字节一致
  Pure Rust, zero Go dependencies; ClientHello byte-for-byte identical to the original's `testdata/` fixtures
- 每条 hello 的边际 CPU 约为原版的 1/8（13.3 µs vs 102 µs，实测协议见 README）
  Marginal CPU per hello ≈ 1/8 of the original's (13.3 µs vs 102 µs; protocol in the READMEs)
- REALITY：鉴权 / 镜像握手 / fallback 透传 / 客户端半边 / stock Xray 真栈
  REALITY: auth / mirror handshake / fallback passthrough / client half / stock-Xray true stack

## License

Apache-2.0（细节见 [README.zh.md](README.zh.md) / [README.en.md](README.en.md) 的 License 节；
vendored rustls 与上游派生夹具的许可见 `THIRD-PARTY.md`）。
Apache-2.0 (details in the License section of [README.zh.md](README.zh.md) /
[README.en.md](README.en.md); vendored rustls and upstream-derived fixture licenses in
`THIRD-PARTY.md`).
