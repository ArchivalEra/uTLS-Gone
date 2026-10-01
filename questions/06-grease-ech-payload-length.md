# 06: GREASE-ECH 的载荷长度是每连接随机，还是固定？

**Status:** resolved

结案：2026-10-01。**结论：每连接随机，而且 uTLS 与 BoringSSL 逐值一致 ——
「uTLS 不保真」这个怀疑被证伪，预设不动。**

## 现象（本仓与参照实现都如此，实测）

本仓产出的 Chrome 133 ClientHello **总长每连接会变** —— 台账事实
`fp_chrome_133_len_stable` 的值是 `NO`。长度的唯一来源是 GREASE-ECH（`0xfe0d`）的载荷：
它从 `{128,160,192,224}`（再按 AEAD 各 +16）里取一个，其余每一部分的长度都固定
（session id 32、公钥长度固定、无填充扩展）。四条总长落在 `{1716,1748,1780,1812}`
（等差数列，与候选表的间距一致）。

## 判据：(b) BoringSSL 源码里的载荷长度 —— **也是四个候选**

出处：`google/boringssl`，`ssl/encrypted_client_hello.cc`，`setup_ech_grease()`：

```c
static size_t random_size(size_t min, size_t max) {          // 行 730
  size_t value;
  RAND_bytes(reinterpret_cast<uint8_t *>(&value), sizeof(value));
  return value % (max - min + 1) + min;
}

// To determine a plausible length for the payload, we estimate the size of a
// typical EncodedClientHelloInner without resumption: …
// Then round up to a multiple of 32, to match RFC 9849, section 6.1.3.
const size_t payload_len =
    32 * random_size(128 / 32, 224 / 32) + aead_overhead(aead);   // 行 770
```

`random_size(4, 7)` 均匀取 `{4,5,6,7}` ⇒ **加密前载荷 ∈ `{128,160,192,224}`**，
再加 `aead_overhead(aead)`（AES-128-GCM = 16，见同文件行 719 的 `EVP_AEAD_max_overhead`）
⇒ 与 uTLS 的候选表**逐值相同**。

uTLS 那一侧（`u_ech.go`）是同一个形状：`CandidatePayloadLens []uint16 // Pre-encryption.
If 0, will pick 128(+16=144)`，用 `rand.Int(rand.Reader, len)` 挑一个索引；Chrome 预设把
四个长度都列上，Firefox 的预置只列一个（所以 Firefox 的 `len_stable` 是 `True`）。

## 结论与它推翻了什么

- **「真实 Chrome 的 ClientHello 长度是稳定的」不成立**：Chrome（BoringSSL）的 GREASE-ECH
  载荷**同样**在四个候选里随机 —— 总长因此也会变。本仓、uTLS、Chrome 三方一致。
- 所以本仓**不需要**改预设，也不需要给 `GreaseEch` 加长度参数；
  `fp_chrome_133_len_stable = NO` 是一个**正确的**观测（Chrome 自己也这样），不是缺陷。
- 原单里那句「怀疑是 uTLS 在这点上不保真」就此**证伪**，别再照着它改东西 ——
  改了反而与参照实现逐字节不一致，而那是本仓的判据。

## 复现（本机有 SOCKS5h 代理 `127.0.0.1:2080`，所以现在拿得到）

```bash
# 注意分支是 main，不是 master —— 上一轮用 master 拿到 codeload 的 404，
# 于是被误记成「codeload 上没有 BoringSSL 那个仓」。
curl -sS --proxy socks5h://127.0.0.1:2080 -o /tmp/bs.tgz \
  https://codeload.github.com/google/boringssl/tar.gz/refs/heads/main
mkdir -p /tmp/bs && tar xzf /tmp/bs.tgz -C /tmp/bs --wildcards '*/ssl/*'
grep -n "random_size(128 / 32, 224 / 32)" /tmp/bs/boringssl-main/ssl/encrypted_client_hello.cc
```

本轮那份 tarball：sha256 `e01eb3267360d3146228dc1e05dd272849f0406bd0ac62ea52310ed719bb26c3`
（约 74 MB）；该源文件：sha256 `99bc4ea5bfb6200456f1dfa69e90dedb16e743ce4bb7702a08af8c8f105c9826`。
**BoringSSL 的 `main` 是移动靶**，所以引用时带上这两个哈希。

**Settling:** `grep -n "random_size(128 / 32, 224 / 32)" ssl/encrypted_client_hello.cc`（源码按上面那两条命令取回）—— 命中且它是一张**候选表 / 随机取值** ⇒ 结论成立（Chrome 也是四选一随机，预设不动）；命中处若是**单个固定值** ⇒ 结论翻转（uTLS 不保真，改预设 + 写 `retractions.json`）。

**Type:** question

- [x] 取到 (a) 或 (b) 中任意一份证据 —— 取到 (b)：`ssl/encrypted_client_hello.cc:770`
- [x] 若 uTLS 确实不保真：把结论写进 `retractions.json` —— **不适用**：uTLS **保真**，
      候选表逐值相同
- [x] 改预设 / 同步 `fp_chrome_133_len_stable` —— **不适用**（同上：改了反而与参照实现不一致）
- [x] 结论回填，`Status:` 改 `resolved`，**别删这个文件**
