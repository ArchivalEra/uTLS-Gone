# 第三方代码与数据（本仓里**不是我们写的**部分）

本仓的**我们自己的代码**按根目录 `LICENSE`（**Apache-2.0**）。

下面两块是第三方代码/数据，各自的许可**随本仓一起保留**，不受我们的许可影响：
`crates/rustls` 是 Apache-2.0/ISC/MIT（`crates/rustls/LICENSE-*` 三份原文），
派生自 uTLS 的夹具与表是 BSD-3-Clause（全文见本文末尾）。
三者的宽松许可是**兼容**的（都可以并入更大作品并保留各自声明），所以整仓分发没有冲突。下面两处是从别处来的，各自的许可在这里说清。

## 1. `crates/rustls/` —— vendored 的 rustls 0.23.45

- 上游：<https://github.com/rustls/rustls>，版本 **0.23.45**。
- 许可：**Apache-2.0 / ISC / MIT**（三选一）。原文就在 `crates/rustls/LICENSE-APACHE`、
  `LICENSE-ISC`、`LICENSE-MIT`，随这份 vendored 副本一起进版本库。
- 改了什么：**9 个文件**带 `FORK(utls-rs)` 标记，改动全在那些标记附近；
  完整补丁在 `crates/rustls-fork/patch.diff`，**可验证**：打到一份全新的 0.23.45 上应得到
  与 `crates/rustls` **逐文件相同**的树（做法见 `crates/rustls-fork/README.md`）。
- 为什么必须 vendored：上游没有公开的 ClientHello 定制 API 且自 0.23.0 起每连接随机化扩展
  顺序 —— 见 `README.md`「为什么必须 fork」。

## 2. 从 `refraction-networking/utls` 派生的数据与表

- 上游：<https://github.com/refraction-networking/utls>，许可 **BSD-3-Clause**
  （原文附在下面；它本身派生自 Go 标准库，所以版权行是 The Go Authors）。
- 派生/搬运的具体内容：
  - `crates/utls/tests/fixtures/utls-testdata/`（55 个 `testdata/` 录音夹具）
    与 `raw-capture.bin`；
  - `crates/utls/tests/fixtures/utls-reference.json`、`utls-randomized.json`
    （用**上游自己的 API** 跑出来的产出，不是转写）；
  - `crates/utls/src/hello/preset_data.rs`、`randomized_tables.rs` 里逐条抄录的
    预设与权重表（来源：上游 `u_parrots.go`、`u_common.go` 等）。
- 为什么搬运：本仓的判据是「与参照实现逐字节一致」，判据本身必须带着上游的原始字节/表
  —— 只抄结论的话，两边一起错也看不出来。出处与对账口径在各 fixtures 目录的 README 里。

### BSD-3-Clause（uTLS，原样附上）

```
Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
