//! **速度与 CPU 消耗**的可复跑测量：走**引擎那道缝**产出一条 ClientHello。
//!
//! # 为什么需要它（以及它对应参照实现的哪一个动作）
//!
//! 「我们的实现有多快」只有在**同一层**上问才有意义。本仓有两个可测的层：
//!
//! | 层 | 动作 | 对应 uTLS 侧 |
//! |---|---|---|
//! | 指纹层 | `ClientHelloSpec::marshal` —— 只把声明编码成字节 | 没有等价物（uTLS 的 spec 必须挂在 UConn 上） |
//! | **引擎层** | `FingerprintClient::plan` —— 起真密钥交换 + 编码 + 记账 | **`tls.UClient(...) + BuildHandshakeState()`** |
//!
//! `crates/utls/tests/fixtures/gen-reference/main.go` 的 `build()` 走的是右边那一行，
//! 所以要与它比就得跑**引擎层**。拿指纹层去比会得到一个虚高的倍数 —— 本轮实测踩到过：
//! 指纹层 4.0 µs/次 vs uTLS 116 µs/次，看着像 29×，其实两层的东西不可比。
//!
//! # 边界：引擎**不为空 spec 产出 hello**，另有两类形态要看清
//!
//! 本程序会把 41 档分成「能建的」与「被拒的（带原因）」两份名单打出来。当前是 40 / 1：
//! 唯一被拒的是 `HelloCustom` = `ClientHelloSpec::empty()`，理由「没有密码套件」——
//! 空 spec 不是一条合法的 ClientHello。
//!
//! 另外两类曾经也发不出去，现在都能建了，各自的边界写在对应的测试里：
//!
//! - **TLS 1.2 时代的老预设**（Chrome 58/62、Firefox 55/56、Ios 11/12、Android 11、360 7）：
//!   spec 里没有 `key_share` ⇒ 引擎产出零交换的 plan（第二飞由引擎自己做 ECDHE）。
//!   判据在 `tests/tls12_presets.rs`：7 档真谈成 `TLSv1_2`；`360_7` 的套件与现代 TLS 栈
//!   交集为 0 ⇒ 服务端回 `HandshakeFailure`（密码套件的性质，不是引擎缺陷）。
//!   用它们时 config 的版本范围要设成 1.2，否则降级哨兵会被判成降级攻击。
//! - **PQ 预设**（ChromePq 115/120、ChromePsk 115）：`X25519Kyber768Draft00` 是草案组，
//!   提供者没有它 ⇒ 给它一个**长度正确**的占位公钥（形状与 Chrome 一致），真交换只交 X25519。
//!   判据在 `tests/pq_key_share.rs`；服务器若认那个草案组并选中它，会响亮失败而不是静默换组。
//!
//! # 用法
//!
//! ```bash
//! cargo build --release --example plan-cost        # 预热
//! ./target/release/examples/plan-cost 'Chrome(70)' 'Chrome(120)'   # 限定预设（可选）
//! ```
//!
//! 判据是**它真的做了那件事**：`checksum=` 是所有产出字节的 FNV-1a ——
//! 少了它就得防「快是因为什么都没干」。
//!
//! # 本轮实测（2026-10-01，Ryzen 9 3900X；`bench/main.go` 是 Go 侧的对等物）
//!
//! 39 档公共交集（两边支持集合的交集 —— bench 名单无 Ios(14)），n=48 与 10n=480 各三次取
//! 中位，单档探针分离一次性初始化（完整矩阵与协议见 README 的测法一节）：
//!
//! | | 首条 hello 前的一次性初始化 | **每条 hello 的边际 CPU** |
//! |---|---|---|
//! | uTLS（Go 1.27，默认构建） | ≈4 ms | **102 µs** |
//! | 本仓（Rust，默认 release） | ≈33 ms | **13.3 µs**（7.7×） |
//! | 本仓（+ fat LTO，CGU=1） | ≈33 ms | 13.2 µs —— 噪声内不变（热点在 crypto 原语，不在内联） |
//!
//! 模型校验：39 档 × 480 条/档（18720 条/进程），实测 Go 1.9185 s / 本仓 283.6 ms ——
//! 线性模型（一次性 + 边际 × 条数）预测 1919 / 283.6 ms，成立。⚠️ 这些是**这台机器**上的；
//! 换机器请重跑，别把数字搬走（`checksum` 也随进程不同，它只用来证明「确实做了事」）。
//! 只跑 48 条就报「µs/条」会把一次性初始化摊不干净（31.6 vs 13.3 µs），是本轮踩过的坑。

use std::sync::Arc;
use std::time::Instant;

use rustls::client::{PlanRequest, SuppliesClientHello};
use rustls::crypto::aws_lc_rs::default_provider;
use utls::hello::{ClientHelloId, ClientHelloSpec};
use utls_engine::FingerprintClient;

/// 每个预设跑几次（uTLS 的参照发生器用 48，这里对齐它）。
/// 可用 `PLANCOST_RUNS` 覆盖 —— 用来把「每进程固定开销」与「每条 hello 的边际成本」分开量：
/// 同一个进程跑 0 条（预设名拼错即可）量固定开销，跑 n 条与 10n 条各量一次解出边际成本。
fn runs() -> usize {
    std::env::var("PLANCOST_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48)
}

fn main() {
    let want: Vec<String> = std::env::args().skip(1).collect();
    let provider = Arc::new(default_provider());
    // 引擎能完成的组：与 `ClientConfig::fork_key_exchange_groups()` 同一口径。
    let groups: Vec<u16> = provider
        .kx_groups
        .iter()
        .filter(|g| g.usable_for_version(rustls::ProtocolVersion::TLSv1_3))
        .map(|g| u16::from(g.name()))
        .collect();

    let mut checksum: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a 起步值
    let (mut units, mut presets) = (0usize, 0usize);
    let mut built: Vec<String> = Vec::new();
    let mut refused: Vec<String> = Vec::new();

    let t0 = Instant::now();
    for id in ClientHelloId::implemented() {
        let name = format!("{id:?}");
        if !want.is_empty() && !want.contains(&name) {
            continue; // 限定时给的是 Debug 形状的名字（`Chrome(70)`）；拼错会体现为 presets=0
        }
        let Ok(spec) = ClientHelloSpec::from_preset(*id) else {
            continue;
        };
        presets += 1;
        let client = FingerprintClient::new(spec, provider.clone()).with_sni("example.com");
        let mut ok = true;
        let mut refused_reason = String::new();
        for _ in 0..runs() {
            let plan = match client.plan(&PlanRequest {
                groups: groups.clone(),
                resumption: None,
            }) {
                Ok(p) => p,
                Err(e) => {
                    ok = false;
                    // 把**原因**也记下来：只看「被拒名单」会以为 12 档是一个问题，
                    // 实际是两类（没有 key_share 的老预设 / 用了提供者不提供的组）。
                    refused_reason = format!("{e}");
                    break;
                }
            };
            let bytes = plan.client_hello.expect("外供路径一定给字节");
            for b in &bytes {
                checksum = (checksum ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3);
            }
            units += 1;
        }
        if ok {
            built.push(name);
        } else {
            refused.push(format!("{name} ← {refused_reason}"));
        }
    }
    println!("presets={presets} runs_each={} units={units}", runs());
    println!("built={}", built.join(","));
    println!("refused_no_usable_key_share={}", refused.join(","));
    println!("elapsed={:?}", t0.elapsed());
    println!("checksum={checksum:016x}");
}
