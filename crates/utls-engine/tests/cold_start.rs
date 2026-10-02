//! **冷启动回归哨兵**：进程内首个密钥交换不该背一次性成本。
//!
//! # 为什么单独立一个二进制、且只有这一个测试
//!
//! aws-lc 的一次性初始化是**进程全局**的：首个碰它的调用付钱。所以「首条 hello 快不快」
//! 只有在**全新进程、且没有别的代码先碰过 RNG**时才有意义。一个只含一个 `#[test]` 的
//! 独立测试二进制正好给出这个环境：测试框架本身不碰密码学，于是下面计时区里的
//! `plan()` 就是这个进程的首次 provider RNG 使用。
//!
//! # 断言什么
//!
//! 首条 hello 的耗时**远低于** jitter-entropy 冷启动的量级。项目根 `.cargo/config.toml`
//! 的 `AWS_LC_SYS_NO_JITTER_ENTROPY=1` 生效时它是 ~0.1 ms（实测 ~110 µs）；若那条配置
//! 被删掉、或提供者换回带 CPU-jitter 熵源的构建，它会跳到 **~32 ms** 并在这里红。
//!
//! 阈值取 10 ms：比 ~0.11 ms 高 **~90×**（噪声吃不下），比 ~32 ms 低 **~3×**（回归必抓到）。

use std::time::{Duration, Instant};

use rustls::client::{PlanRequest, SuppliesClientHello};
use utls::hello::{ClientHelloId, ClientHelloSpec};
use utls::values as v;
use utls_engine::FingerprintClient;

#[test]
fn the_first_hello_does_not_pay_a_jitter_entropy_startup_tax() {
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    // 这个进程的**第一次** provider RNG 使用就发生在下面这段计时里（见模块头：本二进制
    // 只有一个测试，且测试框架不碰密码学）。Chrome(70) 带 X25519 key share ⇒ plan 里会
    // 现起一把交换（走 provider RNG）。
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).expect("预设存在");
    let client = FingerprintClient::new(spec, provider).with_sni("example.com");

    let t = Instant::now();
    let plan = client
        .plan(&PlanRequest {
            groups: vec![v::X25519],
            resumption: None,
        })
        .expect("plan 该产出");
    let first = t.elapsed();
    assert!(
        !plan.client_hello.expect("外供路径一定给字节").is_empty(),
        "别把「快」测成「什么都没干」"
    );

    assert!(
        first < Duration::from_millis(10),
        "首条 hello 花了 {first:?} —— 一次性初始化又回来了：\
         要么 `.cargo/config.toml` 的 AWS_LC_SYS_NO_JITTER_ENTROPY=1 没了（重建才生效），\
         要么提供者换回了带 CPU-jitter 熵源的构建（见该文件与 README 的测法一节）"
    );
    println!("冷进程首条 hello: {first:?}（jitter 熵源关闭时应 ~0.1 ms）");
}
