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
//! # 一个必须说出来的边界：引擎**不为某些预设产出 hello**
//!
//! 引擎要求「至少一把能完成的密钥交换」，否则那条 hello 永远握不上手，所以它**拒绝**
//! （错误信息里会说清是哪些组之间没有交集）。实测 40 档里 **12 档**会被拒：
//!
//! - TLS 1.2 时代的（`Chrome(58)`/`Chrome(62)`/`Firefox(55)`/`Firefox(56)`/`Ios(11)`/
//!   `Ios(12)`/`Android(11)`/`Browser360(7)`）——它们的 spec 里根本没有 `key_share`；
//! - 用的是**提供者不提供的组**（`ChromePq(115)`/`ChromePq(120)`/`ChromePsk(115)` 的
//!   `X25519Kyber768Draft00`，rustls 的 aws-lc-rs 提供者只有 `X25519MLKEM768`）；
//! - `Custom`（空 spec）。
//!
//! **指纹层不受影响**（那些预设的字节照样与 uTLS 逐字节相同，39 条夹具对账全过）——
//! 这条边界只属于**引擎那条路**。与 Go 侧比时要把预设集合对齐：本程序把能建的报出来，
//! 调用方拿它去限定 Go 侧的同名集合。
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
//! 5 档公共子集（`chrome_70/120`、`firefox_120`、`ios_13`、`safari_26`），两个量级各量一次：
//!
//! | | 每进程固定开销 | **每条 hello 的边际 CPU** |
//! |---|---|---|
//! | uTLS（Go） | 1.9 ms | **151 µs** |
//! | 本仓（Rust, release） | 0.7 ms | **26 µs** |
//!
//! 模型校验：同一进程跑 4800 条，实测 Go 0.692 s / 本仓 0.118 s（预测 0.728 / 0.124）——
//! 即**同样的活，本仓 CPU 约 1/6**。⚠️ 这两个数是**这台机器**上的；换机器请重跑，
//! 别把数字搬走（`checksum` 也随进程不同，它只用来证明「确实做了事」）。
//! 只跑 48 条就报「µs/条」会把启动开销当成本体，是本轮踩过的坑 —— 见 README 的测法一节。

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
    std::env::var("PLANCOST_RUNS").ok().and_then(|v| v.parse().ok()).unwrap_or(48)
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
        for _ in 0..runs() {
            let plan = match client.plan(&PlanRequest { groups: groups.clone(), resumption: None }) {
                Ok(p) => p,
                Err(_) => {
                    ok = false;
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
            refused.push(name);
        }
    }
    println!("presets={presets} runs_each={} units={units}", runs());
    println!("built={}", built.join(","));
    println!("refused_no_usable_key_share={}", refused.join(","));
    println!("elapsed={:?}", t0.elapsed());
    println!("checksum={checksum:016x}");
}
