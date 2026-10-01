//! **`Roller`**：按顺序重试多个预设，并记住第一个能通的。
//!
//! uTLS 的 `u_roller.go` 是同一件事：一个「哪条指纹能通就用哪条」的拨号器，
//! 用来对付「某个预设被中间盒拦了」这种情况 —— 换一个再试，并把成功的那条**记住**，
//! 后续连接先试它。
//!
//! # 逐条对照 uTLS 的语义（`u_roller.go::Dial`）
//!
//! | uTLS | 这里 |
//! |---|---|
//! | 复制 `HelloIDs` 并**打乱**（用它自己的 PRNG） | 一样，但种子由调用方给（[`Roller::with_seed`]）—— 可复现 |
//! | 记住的 `WorkingHelloID` **提到最前** | 一样（不在列表里就插到最前） |
//! | **TCP 拨号失败 ⇒ 立刻返回**，不再试别的预设 | 一样（`TcpStream::connect_timeout` 的错误直接返回） |
//! | **TLS 握手失败 ⇒ 换下一个预设** | 一样 |
//! | 成功后把 `client.ClientHelloID` 记为 `WorkingHelloID` | 一样（[`Roller::working_hello_id`]） |
//! | 全部失败 ⇒ 返回**最后一个**错误 | 一样 |
//! | `NewRoller` 用 PRNG 随机化两个超时（`7 + Intn(14)` 秒 / `11 + Intn(20)` 秒） | 一样从同一个种子抽（同样的上下界）—— 时间不是指纹，但**复现**要能关掉随机 |
//!
//! # 为什么把「建连」做成参数
//!
//! uTLS 的 `Dial` 里写死了 `UClient(tcpConn, nil, helloID)`，于是它只能打公网。
//! 这里的 `dial` 收一个「拿已有 socket 去谈 TLS」的闭包（[`TlsConnect`]），
//! 于是判据可以用本地服务端（自签证书）跑 —— 而**策略**（顺序、记住、TCP/TLS 两类失败的
//! 不同处置）与**传输**因此各自可换。uTLS 那边的两个失败分支在闭包外，所以那条区别照旧成立。
//!
//! uTLS **没有** `Roller` 的测试（只有 `examples/old/examples.go` 里一个用法示例），
//! 所以这条的判据是本仓自己搭的：本地服务端 + 「失败预设不产字节、成功预设产一条」这种可数的事实。

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::crypto::CryptoProvider;
use utls::hello::{ClientHelloId, ClientHelloSpec};

use crate::{FingerprintClient, UConn};

/// 拿一条已连好的 socket 去谈 TLS，成功则返回 `UConn`。
///
/// 失败分两类，而 `Roller` 对它们的处置不同（见模块头）：**TCP 连不上**立刻放弃，
/// **TLS 谈不成**换下一个预设。所以 TCP 那一步必须由 `Roller` 自己做。
pub type TlsConnect<'a> = &'a mut dyn FnMut(
    TcpStream,
    FingerprintClient,
    &str,
) -> Result<UConn, Box<dyn std::error::Error>>;

/// uTLS `u_roller.go` 的等价物。
pub struct Roller {
    hello_ids: Vec<ClientHelloId>,
    working: Option<ClientHelloId>,
    seed: [u8; 32],
    tcp_timeout: Duration,
    tls_timeout: Duration,
    provider: Arc<CryptoProvider>,
}

impl Roller {
    /// 默认候选表：与 uTLS `NewRoller` 逐条相同（Chrome / Firefox / iOS / Randomized）。
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        Roller {
            hello_ids: vec![
                ClientHelloId::Chrome(latest(CHROME_VERSIONS)),
                ClientHelloId::Firefox(latest(FIREFOX_VERSIONS)),
                ClientHelloId::Ios(latest(IOS_VERSIONS)),
                ClientHelloId::Randomized,
            ],
            working: None,
            seed: random_seed(&provider),
            tcp_timeout: Duration::from_secs(7),
            tls_timeout: Duration::from_secs(11),
            provider,
        }
    }

    pub fn with_hello_ids(mut self, ids: Vec<ClientHelloId>) -> Self {
        self.hello_ids = ids;
        self
    }

    /// 固定种子：打乱候选与随机化超时都从它派生 ⇒ 整条策略可复现。
    pub fn with_seed(mut self, seed: [u8; 32]) -> Self {
        self.seed = seed;
        self
    }

    pub fn with_timeouts(mut self, tcp: Duration, tls: Duration) -> Self {
        self.tcp_timeout = tcp;
        self.tls_timeout = tls;
        self
    }

    /// 上一条连通的预设（uTLS 的 `WorkingHelloID`）。
    pub fn working_hello_id(&self) -> Option<ClientHelloId> {
        self.working
    }

    /// 这一轮的**候选顺序**：记住的那条排最前，其余按种子打乱。
    ///
    /// 单列出来是为了让判据能直接看顺序，而不必从线上字节反推。
    /// 顺序在 `dial` 的每一轮重新算（uTLS 也是每次 `Dial` 重算）。
    pub fn candidate_order(&self) -> Vec<ClientHelloId> {
        let mut order = self.hello_ids.clone();
        if order.is_empty() {
            return order;
        }
        shuffle(&mut order, &self.seed);

        if let Some(working) = self.working {
            // uTLS：找到就与第 0 位互换；找不到就插到最前。
            if let Some(i) = order.iter().position(|id| *id == working) {
                order.swap(0, i);
            } else {
                order.insert(0, working);
            }
        }
        order
    }

    /// 这一轮要用的两个超时（uTLS 在 `NewRoller` 里随机化，上下界照抄）。
    pub fn timeouts(&self) -> (Duration, Duration) {
        let mut s = self.seed;
        let a = 7 + (next_below(&mut s, 14) as u64);
        let b = 11 + (next_below(&mut s, 20) as u64);
        // 调用方显式给过超时就用它的（`with_timeouts` 与随机化二选一，后者是默认）。
        if self.tcp_timeout != Duration::from_secs(7) || self.tls_timeout != Duration::from_secs(11)
        {
            return (self.tcp_timeout, self.tls_timeout);
        }
        (Duration::from_secs(a), Duration::from_secs(b))
    }

    /// 依次试候选，返回**第一条谈成的**连接与它的预设。
    ///
    /// 与 uTLS 的两处关键区别都在这段里：TCP 失败**立刻返回**（不再试别的），
    /// TLS 失败才换下一个；全失败返回**最后一个**错误。
    pub fn dial(
        &mut self,
        addr: SocketAddr,
        server_name: &str,
        tls: TlsConnect<'_>,
    ) -> Result<(UConn, ClientHelloId), Box<dyn std::error::Error>> {
        let (tcp_timeout, tls_timeout) = self.timeouts();
        let order = self.candidate_order();
        if order.is_empty() {
            return Err("utls-engine: Roller 的候选表是空的".into());
        }

        let mut last_err: Option<Box<dyn std::error::Error>> = None;
        for id in order {
            // 预设本身拿不到（例如 `Golang` 在本架构里没有 spec）⇒ 这个候选不可用，
            // 换下一个。这与 uTLS 里 `UTLSIdToSpec` 失败时 `UClient` 直接报错的效果一致：
            // 那条候选谈不成。
            let spec = match client_spec(id) {
                Ok(spec) => spec,
                Err(e) => {
                    last_err = Some(Box::new(e));
                    continue;
                }
            };

            // TCP：失败**立刻**返回（uTLS 的 `return nil, err`）。
            let sock = match TcpStream::connect_timeout(&addr, tcp_timeout) {
                Ok(sock) => sock,
                Err(e) => return Err(Box::new(e)),
            };

            // TLS：失败换下一个。
            let client = FingerprintClient::new(spec, self.provider.clone())
                .with_sni(server_name.to_string());
            match tls(sock, client, server_name) {
                Ok(conn) => {
                    // 谈成了：记住它，下一轮先试它。
                    self.working = Some(id);
                    return Ok((conn, id));
                }
                Err(e) => {
                    let _ = tls_timeout; // 超时由闭包施加（它知道自己是阻塞还是非阻塞）
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| "utls-engine: Roller 没有任何候选".into()))
    }
}

/// uTLS 的 `HelloXxx_Auto` 是「该家族里最新的那一版」，而本仓的 `ClientHelloId` 用
/// **显式版本号**表达（`preset.rs` 的理由：隐式的「最新」会随升级漂移）。
/// 所以这里把「最新」在**构造候选表的那一刻**就展开成具体版本；版本清单与本仓
/// `implemented()` 同源（家族内的那些版本）。
fn latest(versions: &[u16]) -> u16 {
    *versions.iter().max().expect("该家族至少有一个版本")
}

const CHROME_VERSIONS: &[u16] = &[58, 62, 70, 72, 83, 87, 96, 100, 102, 106, 120, 131, 133];
const FIREFOX_VERSIONS: &[u16] = &[55, 56, 63, 65, 99, 102, 105, 120, 148];
const IOS_VERSIONS: &[u16] = &[11, 12, 13];

/// 把 id 变成 spec（`Golang` / 随机化家族在这里会失败 —— 那正是「这条候选谈不成」）。
fn client_spec(id: ClientHelloId) -> Result<ClientHelloSpec, utls::hello::SpecError> {
    ClientHelloSpec::from_preset(id)
}

/// Fisher–Yates，用从种子派生的字节流。
///
/// 与 uTLS 的 `rand.Shuffle` 不必逐位相同 —— 那里的种子是 OS 熵，本来就不可复现。
/// 这里要的是「同一颗种子给同一个顺序」，所以用最直白的写法。
fn shuffle<T>(xs: &mut [T], seed: &[u8; 32]) {
    let mut s = *seed;
    for i in (1..xs.len()).rev() {
        let j = next_below(&mut s, (i + 1) as u32) as usize;
        xs.swap(i, j);
    }
}

/// 从种子派生的一个小于 `n` 的数（SHAKE 太重伤，这里只需要「可复现的伪随机」）。
fn next_below(seed: &mut [u8; 32], n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    // 一个极简的 xorshift：**不是**密码学安全，也不需要是 —— 它只决定尝试顺序。
    let mut x = u64::from_be_bytes(seed[..8].try_into().expect("8 字节"));
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    seed[..8].copy_from_slice(&x.to_be_bytes());
    (x % u64::from(n)) as u32
}

/// 默认种子：从引擎的密码学随机源取（`CryptoProvider::secure_random`）。
///
/// 不用 `getrandom` 直连：引擎已经有一个**可注入**的随机源，与 `HandshakeInputs::os()`
/// 同一处熵；这样整套测试里换 provider 就能一并换掉随机性。
fn random_seed(provider: &CryptoProvider) -> [u8; 32] {
    let mut s = [0u8; 32];
    provider.secure_random.fill(&mut s).expect("OS 熵源不可用");
    s
}
