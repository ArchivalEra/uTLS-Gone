//! **`warm_up` 的功能判据**：成功、可重复调用、不改任何可观测行为 —— 以及这个 API
//! 仍然好用。**一次性成本本身已从源头消除**（见下），所以「预付」现在多半无物可预付；
//! 本文件保留为 `warm_up` 的功能判据。
//!
//! # 背景与现状（2026-10-02 定位 → 从源头解决）
//!
//! aws-lc 的进程内首次 `RAND_bytes` 曾要 **~33 ms** —— 纯用户态的 CPU-jitter-entropy
//! 收集（`strace -c`：全进程系统调用总共 0.4 ms；第二次 fill **~330 ns**；先 keygen 同样
//! 要付，keygen 内部走 RAND）。上游 [aws-lc-rs#1140](https://github.com/aws/aws-lc-rs/issues/1140)
//! 开着、`aws_lc_rs::init()` 是空操作 —— 当时只能靠真做一次密码学操作来预付（`warm_up`）。
//!
//! 现在**不再需要**：项目根 [`.cargo/config.toml`](../../../.cargo/config.toml) 设了
//! `AWS_LC_SYS_NO_JITTER_ENTROPY=1`，把熵源换成「OS CSPRNG + RDRAND」，首条 hello 从
//! ~32 ms 降到 ~0.11 ms。冷启动本身由 [`cold_start.rs`](../cold_start.rs) 判
//! （独立进程、单独一个测试，阈值哨兵）。
//!
//! 判据口径：功能判据进 CI；延迟判据 `#[ignore]`（量本机时钟，不进门禁），
//! 判据取**差**不取绝对值 —— 无物可预付时只打印、不断言。

mod common;

use std::time::{Duration, Instant};

use rustls::client::{PlanRequest, SuppliesClientHello};
use utls::hello::{ClientHelloId, ClientHelloSpec};
use utls::values as v;
use utls_engine::{FingerprintClient, warm_up};

fn provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

fn chrome70(p: std::sync::Arc<rustls::crypto::CryptoProvider>) -> FingerprintClient {
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap();
    FingerprintClient::new(spec, p).with_sni("example.com")
}

/// 功能判据（进 CI）：warm_up 成功、可重复调用；之后的 plan 照常产出、形状照旧。
#[test]
fn warm_up_succeeds_is_idempotent_and_plan_still_works() {
    let p = provider();
    warm_up(&p).expect("warm_up 该成功");
    warm_up(&p).expect("warm_up 该可重复调用");

    let plan = chrome70(p)
        .plan(&PlanRequest {
            groups: vec![v::X25519],
            resumption: None,
        })
        .expect("预热之后的 plan 该照常产出");
    let bytes = plan.client_hello.expect("外供路径一定给字节");
    assert!(!bytes.is_empty(), "预热不该吃掉 hello 的字节");
    // 形状没被 warm_up 动过：X25519 的 share 还在，长度还是 32 字节的公钥。
    let entries = key_share_entries(&bytes);
    assert!(
        entries.iter().any(|(g, l)| *g == v::X25519 && *l == 32),
        "预热之后的 hello 该仍带 32 字节的 X25519 共享：{entries:?}"
    );
}

/// 延迟判据（`--ignored` 人手跑）：预热后的首条 plan 必须比预热本身便宜两个量级（≥100×）。
///
/// 实测比值 ~250×（32.6 ms 的 warm_up vs 128 µs 的首条 plan —— 后者含 `from_preset`
/// 与 `FingerprintClient::new`）。用差值而不是绝对值：warm_up 没付到钱（同进程其它
/// 测试先付过 / 提供者无一次性成本）时只打印数字、不断言 —— 那种情形下「预付」
/// 无物可验，硬断言只会 flaky。
#[test]
#[ignore = "量本机时钟：人手跑（-- --ignored），不进门禁"]
fn the_first_plan_after_warm_up_is_cheap() {
    let p = provider();
    let t = Instant::now();
    warm_up(&p).expect("warm_up");
    let warm = t.elapsed();

    let t = Instant::now();
    let plan = chrome70(p)
        .plan(&PlanRequest {
            groups: vec![v::X25519],
            resumption: None,
        })
        .expect("plan");
    let first = t.elapsed();
    assert!(
        !plan.client_hello.expect("外供路径一定给字节").is_empty(),
        "预热不该吃掉 hello 的字节"
    );

    println!("warm_up（预付一次性初始化）: {warm:?}");
    println!("预热后的首条 plan          : {first:?}");

    // 绝对上限：预热后的 plan 里不该再有一次性的 ms 级成本（回归哨兵；上限放得宽）。
    assert!(
        first < Duration::from_millis(5),
        "预热后的首条 plan 花了 {first:?} —— 一次性初始化没有被预付掉"
    );
    // 相对判据：只有当 warm_up 真付了钱（≥1 ms）才有得比；此时 plan 要便宜 ≥100×。
    if warm.as_millis() >= 1 {
        assert!(
            first.as_nanos().saturating_mul(100) < warm.as_nanos(),
            "预热后的 plan（{first:?}）该比 warm_up 本身（{warm:?}）便宜两个量级以上"
        );
    } else {
        println!("（warm_up 没付到钱 —— 同进程已付过或提供者无一次性成本；只打印，不断言）");
    }
}

/// 从一条 hello **握手消息**里取 `key_share` 的 `(组, 公钥长)` 列表
/// （与 `pq_key_share.rs` / `p256_handshake.rs` 的本地解析同款）。
fn key_share_entries(message: &[u8]) -> Vec<(u16, usize)> {
    let mut p = 4 + 2 + 32;
    p += 1 + message[p] as usize; // legacy_session_id
    let cs = u16::from_be_bytes([message[p], message[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + message[p] as usize; // compression_methods
    let n = u16::from_be_bytes([message[p], message[p + 1]]) as usize;
    p += 2;
    let region = &message[p..p + n];
    let mut q = 0usize;
    while q + 4 <= region.len() {
        let ty = u16::from_be_bytes([region[q], region[q + 1]]);
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        let body = &region[q + 4..q + 4 + bl];
        if ty == 0x0033 {
            let mut out = Vec::new();
            let mut r = 2usize;
            while r + 4 <= body.len() {
                let g = u16::from_be_bytes([body[r], body[r + 1]]);
                let kl = u16::from_be_bytes([body[r + 2], body[r + 3]]) as usize;
                out.push((g, kl));
                r += 4 + kl;
            }
            return out;
        }
        q += 4 + bl;
    }
    Vec::new()
}
