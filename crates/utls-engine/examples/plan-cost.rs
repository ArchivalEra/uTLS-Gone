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
//! cargo build --release --example plan-cost        # 构建
//! ./target/release/examples/plan-cost 'Chrome(70)' 'Chrome(120)'   # 限定预设（可选）
//! PLANCOST_BREAKDOWN=1 ./target/release/examples/plan-cost 'Chrome(70)'  # 首条分步归因（stderr）
//! PLANCOST_EACH=1 ./target/release/examples/plan-cost 'Chrome(70)'      # 逐条计时（stderr）
//! PLANCOST_WARM=1 ./target/release/examples/plan-cost 'Chrome(70)' # 先 warm_up 再计时（现已有无不影响）
//! ```
//!
//! 判据是**它真的做了那件事**：`checksum=` 是所有产出字节的 FNV-1a ——
//! 少了它就得防「快是因为什么都没干」。
//!
//! # 本轮实测（2026-10-03，Ryzen 9 3900X；`bench/main.go` 是 Go 侧的对等物）
//!
//! 39 档公共交集（两边支持集合的交集 —— bench 名单无 Ios(14)），n=48 与 10n=480 各三次取
//! 中位，单档探针分离一次性初始化（完整矩阵与协议见 README 的测法一节）：
//!
//! | | 首条 hello（冷进程） | **每条 hello 的边际 CPU** |
//! |---|---|---|
//! | uTLS（Go 1.27，默认构建） | ~77 µs | **102 µs** |
//! | 本仓（Rust，默认 release） | **~69 µs** | **13.3 µs**（7.7×） |
//! | 本仓（+ fat LTO，CGU=1） | ~69 µs | 13.2 µs —— 噪声内不变（热点在 crypto 原语，不在内联） |
//!
//! 一次性成本分两段清掉（`PLANCOST_BREAKDOWN=1` 是归因工具）：
//!
//! 1. **~33 ms**：aws-lc 进程内首次 `RAND_bytes` 的 CPU-jitter 熵收集 —— 项目根
//!    `.cargo/config.toml` 的 `AWS_LC_SYS_NO_JITTER_ENTROPY=1` 换掉熵源（32.4 ms →
//!    ~0.11 ms，消 99.6%）；
//! 2. **~110 → ~69 µs**：剩余的 keygen 仍要替 aws-lc 的 DRBG 实例化付 ~35-46 µs
//!    （`EphemeralPrivateKey::generate(alg, _rng)` 忽略 rng 参数）——
//!    `crates/x25519-os` 把 X25519 的 keygen 熵源换成内核 CSPRNG（算术仍是 aws-lc）；
//!    指纹层的两次取熵合成一次 syscall。
//!
//! `PLANCOST_WARM=1` 仍能跑 `utls_engine::warm_up`，但已无钱可预付。
//! TLS 1.2 时代的档（Chrome 58/62 等）全程不碰 provider RNG，单条 ~50 µs。
//!
//! # 内存（2026-10-02 加的口径）
//!
//! `alloc_bytes=` = 计时区内的累计堆分配（计数分配器，realloc 按新尺寸计；与 Go 侧
//! `runtime.MemStats.TotalAlloc` 同口径，见 `gen-reference/bench/main.go`）。
//! `PLANCOST_FRESH=1` 每条 hello 新建规划器 —— 对齐 uTLS「每连接一个 UClient」的形状，
//! 两种口径都量得出来。峰值 RSS 用 `getrusage(RUSAGE_CHILDREN)` 量（本机实测两边都
//! ~16 MB，且空跑 = 18720 条 —— 谁都不随条数涨）。
//!
//! 模型校验：39 档 × 480 条/档（18720 条/进程），实测 Go 1.9185 s / 本仓 283.6 ms ——
//! 线性模型（一次性 + 边际 × 条数）预测 1919 / 283.6 ms，成立。⚠️ 这些是**这台机器**上的；
//! 换机器请重跑，别把数字搬走（`checksum` 也随进程不同，它只用来证明「确实做了事」）。
//! 只跑 48 条就报「µs/条」会把一次性初始化摊不干净（31.6 vs 13.3 µs），是本轮踩过的坑。

use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::{PlanRequest, SuppliesClientHello};
use rustls::crypto::aws_lc_rs::default_provider;
use utls::hello::{ClientHelloId, ClientHelloSpec};
use utls_engine::FingerprintClient;

/// 累计分配字节计数器：`alloc_bytes=` 行的来源。只增不减（realloc 按新尺寸计），
/// 口径与 Go 侧 `runtime.MemStats.TotalAlloc` 相同 —— 量「分配了多少」，不是「占着多少」
/// （后者是 RSS 的事，见 README 的内存行）。
mod counting {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicU64, Ordering};

    pub static TOTAL: AtomicU64 = AtomicU64::new(0);

    pub struct Counting;

    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            TOTAL.fetch_add(layout.size() as u64, Ordering::Relaxed);
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            TOTAL.fetch_add(new_size as u64, Ordering::Relaxed);
            unsafe { System.realloc(ptr, layout, new_size) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            TOTAL.fetch_add(layout.size() as u64, Ordering::Relaxed);
            unsafe { System.alloc_zeroed(layout) }
        }
    }
}

#[global_allocator]
static GLOBAL: counting::Counting = counting::Counting;

/// 每个预设跑几次（uTLS 的参照发生器用 48，这里对齐它）。
/// 可用 `PLANCOST_RUNS` 覆盖 —— 用来把「每进程固定开销」与「每条 hello 的边际成本」分开量：
/// 同一个进程跑 0 条（预设名拼错即可）量固定开销，跑 n 条与 10n 条各量一次解出边际成本。
fn runs() -> usize {
    std::env::var("PLANCOST_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(48)
}

/// `PLANCOST_BREAKDOWN=1`：把**首条** hello 拆到步（provider 构建 / 预设构建 / 规划器
/// 构建 / 纯首 RAND / 首把 keygen / 预付后的 plan / 稳态 plan），stderr 打表。
///
/// 用途：一次性成本归因。例：首条 hello ~120 µs 而边际 ~12 µs ⇒ 差的 ~108 µs 花在哪一步，
/// 这张表直接给答案。量完即走，不改变默认计时的形状。
fn breakdown(provider: &Arc<rustls::crypto::CryptoProvider>) {
    use rustls::client::{PlanRequest, SuppliesClientHello};
    use utls::hello::{ClientHelloId, ClientHelloSpec};
    use utls::values as v;

    let step = |name: &str, t: Instant| eprintln!("{name:<28} {:?}", t.elapsed());

    let t = Instant::now();
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).expect("预设存在");
    step("from_preset(Chrome70)", t);

    let t = Instant::now();
    let client = FingerprintClient::new(spec.clone(), Arc::clone(provider)).with_sni("example.com");
    step("FingerprintClient::new", t);

    // 纯首 RAND（32 字节 fill）—— DRBG 实例化 + OS/RDRAND 取熵都在这里面。
    let t = Instant::now();
    utls_engine::warm_up(provider).expect("warm_up");
    step("first RAND (warm_up, 32B)", t);
    let t = Instant::now();
    utls_engine::warm_up(provider).expect("warm_up");
    step("second RAND (warm)", t);

    // 指纹层的熵输入（utls 自己的 getrandom 路径，与 aws-lc 的 RAND 独立）：
    // 首次调用含 getrandom crate 的懒初始化 + 系统调用。
    let t = Instant::now();
    let _ = utls::hello::HandshakeInputs::os();
    step("HandshakeInputs::os() #1", t);
    let t = Instant::now();
    let _ = utls::hello::HandshakeInputs::os();
    step("HandshakeInputs::os() #2", t);

    // 首把 keygen（X25519）—— RAND 已付过，这里是 keygen 本身 + 组的首次触达。
    let t = Instant::now();
    let x25519 = provider
        .kx_groups
        .iter()
        .find(|g| u16::from(g.name()) == v::X25519)
        .expect("提供者有 X25519");
    let _kx = x25519.start().expect("keygen");
    step("first keygen (X25519.start)", t);
    let t = Instant::now();
    let _kx = x25519.start().expect("keygen");
    step("second keygen (warm)", t);

    // 预付后的 plan：一次性成本里除 RAND/keygen 之外的部分（转录、GREASE、乱序、 marshal）。
    let t = Instant::now();
    let plan = client
        .plan(&PlanRequest {
            groups: vec![v::X25519],
            resumption: None,
        })
        .expect("plan");
    step("plan (rand+keygen pre-paid)", t);
    assert!(!plan.client_hello.expect("字节").is_empty());

    // 稳态：同一条规划器再来一条。
    let t = Instant::now();
    let _ = client
        .plan(&PlanRequest {
            groups: vec![v::X25519],
            resumption: None,
        })
        .expect("plan");
    step("plan #2 (steady state)", t);

    // 全新规划器的 plan（对齐「每连接一个 UClient」）。
    let t = Instant::now();
    let fresh = FingerprintClient::new(spec, Arc::clone(provider)).with_sni("example.com");
    let _ = fresh
        .plan(&PlanRequest {
            groups: vec![v::X25519],
            resumption: None,
        })
        .expect("plan");
    step("fresh client + plan", t);
}

fn main() {
    let want: Vec<String> = std::env::args().skip(1).collect();
    // 与 UClient::new() 同一条 provider 构成：X25519 keygen 用内核 CSPRNG。
    let provider = Arc::new(x25519_os::with_os_random_x25519(default_provider()));
    // 引擎能完成的组：与 `ClientConfig::fork_key_exchange_groups()` 同一口径。
    let groups: Vec<u16> = provider
        .kx_groups
        .iter()
        .filter(|g| g.usable_for_version(rustls::ProtocolVersion::TLSv1_3))
        .map(|g| u16::from(g.name()))
        .collect();

    // PLANCOST_BREAKDOWN=1：首条 hello 的分步归因（stderr），然后照常跑主循环。
    if std::env::var("PLANCOST_BREAKDOWN").as_deref() == Ok("1") {
        breakdown(&provider);
    }

    // PLANCOST_WARM=1：t0 之前先 `warm_up()`（预付 aws-lc 首次 RAND 的 ~33 ms
    // jitter-entropy，见 `utls_engine::warm_up` 的文档），用来把「预热后的首条 hello」
    // 与冷进程分开量。默认保持冷测量 —— 那是真实 CLI 的体验。
    if std::env::var("PLANCOST_WARM").as_deref() == Ok("1") {
        let t = Instant::now();
        utls_engine::warm_up(&provider).expect("warm_up");
        eprintln!("warm_up（预付一次性初始化）: {:?}", t.elapsed());
    }

    // PLANCOST_FRESH=1：每条 hello 都新起一个 FingerprintClient —— 对齐 uTLS「每连接一个
    // UClient」的真实形状，把「复用规划器」与「每连接新建」两种口径的分配都量得出来。
    let fresh = std::env::var("PLANCOST_FRESH").as_deref() == Ok("1");
    // PLANCOST_EACH=1：逐条计时（stderr 打前 12 条的单独耗时）—— 看一次性成本
    // 衰减到边际成本要几条。
    let each = std::env::var("PLANCOST_EACH").as_deref() == Ok("1");
    let mut each_times: Vec<Duration> = Vec::new();

    let mut checksum: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a 起步值
    let (mut units, mut presets) = (0usize, 0usize);
    let mut built: Vec<String> = Vec::new();
    let mut refused: Vec<String> = Vec::new();

    let alloc0 = counting::TOTAL.load(std::sync::atomic::Ordering::Relaxed);
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
        let client = FingerprintClient::new(spec.clone(), provider.clone()).with_sni("example.com");
        let mut ok = true;
        let mut refused_reason = String::new();
        for _ in 0..runs() {
            // fresh 模式下每条 hello 一个新规划器；默认复用外层那把（spec 是数据，进程内可缓存）。
            let per_conn = fresh.then(|| {
                FingerprintClient::new(spec.clone(), provider.clone()).with_sni("example.com")
            });
            let t_each = each.then(Instant::now);
            let plan = match per_conn.as_ref().unwrap_or(&client).plan(&PlanRequest {
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
            if let Some(t) = t_each {
                each_times.push(t.elapsed());
            }
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
    if each {
        let head: Vec<String> = each_times
            .iter()
            .take(12)
            .enumerate()
            .map(|(i, t)| format!("#{i}={t:?}"))
            .collect();
        eprintln!("each: {}", head.join(" "));
    }
    println!("presets={presets} runs_each={} units={units}", runs());
    println!("built={}", built.join(","));
    println!("refused_no_usable_key_share={}", refused.join(","));
    println!("elapsed={:?}", t0.elapsed());
    println!("checksum={checksum:016x}");
    println!(
        "alloc_bytes={}",
        counting::TOTAL.load(std::sync::atomic::Ordering::Relaxed) - alloc0
    );
}
