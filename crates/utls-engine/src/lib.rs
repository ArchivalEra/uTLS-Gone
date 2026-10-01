//! **引擎侧**：把 [`utls`] 产出的 ClientHello 接进一次真实握手。
//!
//! # 这一层为什么存在
//!
//! `utls` 那一层**不引用任何 rustls 类型**（`README.md` 里那条单向依赖）。所以「把字节
//! 交给引擎」这件事必须发生在另一侧的薄适配层里 —— 就是这个 crate。它做三件事：
//!
//! 1. **生成密钥交换**，并把它交给指纹层当输入。密钥生成走 rustls 的密码学提供者 ——
//!    于是 `utls` 里一行密码学都不用有，而「长度进指纹」的那部分（公钥字节数）是真的。
//! 2. 调 `spec.marshal(&inputs)` 拿到 ClientHello 字节。
//! 3. 把字节塞进 fork 出来的 [`ClientHelloPlan`]，让 rustls **原样**使用它。
//!
//! # 与 uTLS 的对应关系
//!
//! uTLS 的 `UConn` 同时是「指纹层」和「连接层」。这里把两者拆开：`utls` 是前者，
//! 本 crate 是后者。拆分的好处是前者可以完全离线、可复现、可对账（见
//! `crates/utls/tests/utls_conformance.rs`），而后者只承担「接进引擎」这一件事。
//!
//! # 这一层现在覆盖什么（**这份清单被逐条判过，别再照旧稿抄**）
//!
//! 下面每一条都有一个可复跑的判据，判据在括号里；**曾经**这里写着「只能完成一个组、
//! HRR 用不了、resumption/PSK/ECH 都没做」——那些话在 2026-10 之前是对的，之后逐条
//! 被推翻，而清单没人改，于是文档开始**低估**自己（比高估更容易误导后来的人）。
//!
//! - **多个组**：`key_share` 里每个引擎能完成的组都会拿到一把真交换
//!   （`tests/multi_key_share.rs`：服务端选中**第二个**组也谈成）。
//! - **混合/经典共用材料**：spec 声明了 `KeyShare::reuse` 时只交一把混合交换，
//!   经典条目的公钥取它的经典分量（`tests/key_share_reuse.rs`，Firefox 148）。
//! - **HelloRetryRequest**：第二飞复用第一飞的输入、只改 `key_share`/cookie/PSK/padding
//!   （`tests/hello_retry.rs`、`tests/hello_retry_e2e.rs`，另有上游夹具的第二飞逐字节对账）。
//! - **会话复用 / PSK**：binder 由引擎在拿到字节后算，我们只留占位（`tests/resumption.rs`：
//!   服务端在第二条连接上说 `Resumed`）。
//! - **真实 ECH**：三族真服务器报 `Accepted`，另有离线判据（`tests/ech_e2e.rs`、
//!   `tests/ech_utls_server.rs`；内层与 uTLS 逐字节相同）。
//! - **TLS 1.2 时代的指纹**（没有 `key_share` 的 8 档）：`tests/tls12_presets.rs`。
//!
//! 仍然**没做**的（如实写）：early data（0-RTT）；QUIC 那条路（`u_quic*.go` 的指纹层
//! 尚未移植，见 `docs/utls-parity.md`）。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

pub mod ech;
pub mod roller;

use rustls::client::{
    ClientHelloPlan, EchOffer, ExternalKeyExchange, HelloRetryRequestPlan, PlanRequest,
    PskBinderSlot, ResumptionOffer, SuppliesClientHello,
};
use rustls::crypto::{ActiveKeyExchange, CryptoProvider, SupportedKxGroup};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, Error, RootCertStore, StreamOwned};
use utls::hello::{
    ClientHelloSpec, CodePoint, Extension, HandshakeInputs, PreSharedKey, PskIdentity, Variability,
    parse_ech_config_list, pick_ech_config,
};
use utls::values as v;

/// 把 rustls 自己的 `ActiveKeyExchange` 包成 fork 要的 [`ExternalKeyExchange`]。
///
/// 为什么是「包」而不是「自己算」：密钥生成留给 rustls 的提供者，本层只负责
/// **决定用哪个组**、以及把公钥字节**原样**交给指纹层。这样 `utls` 不需要任何密码学依赖，
/// 而共享密钥仍然是引擎算的。
struct RustlsKx {
    group: u16,
    pub_key: Vec<u8>,
    /// 混合组的经典那一半（`(组, 公钥)`）。构造时就取好 —— `complete` 之后就拿不到了
    /// （它消费掉整个交换）。
    hybrid_pub: Option<(u16, Vec<u8>)>,
    /// `complete` 与 `complete_hybrid_component` 都要求 `self: Box<Self>`（消费），
    /// 而 fork 的 trait 签名是 `&self`，所以用 `Option` + `take()` 表达「只能用一次」。
    inner: Mutex<Option<Box<dyn ActiveKeyExchange>>>,
}

impl std::fmt::Debug for RustlsKx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsKx")
            .field("group", &format_args!("0x{:04x}", self.group))
            .field("pub_key_len", &self.pub_key.len())
            .field("hybrid", &self.hybrid_pub.is_some())
            .finish()
    }
}

impl RustlsKx {
    fn start(group: u16, provider: &CryptoProvider) -> Result<Self, Error> {
        // `provider.kx_groups` 是 `Vec<&'static dyn SupportedKxGroup>`，不是 Arc。
        let skxg: &dyn SupportedKxGroup = *provider
            .kx_groups
            .iter()
            .find(|g| u16::from(g.name()) == group)
            .ok_or_else(|| {
                Error::General(format!(
                    "utls-engine: 密码学提供者不提供组 0x{group:04x} —— \
                     这个组的 key_share 没法完成握手（要么换组，要么换提供者）"
                ))
            })?;
        let kx = skxg.start()?;
        let pub_key = kx.pub_key().to_vec();
        let hybrid_pub = kx
            .hybrid_component()
            .map(|(g, k)| (u16::from(g), k.to_vec()));
        Ok(RustlsKx {
            group,
            pub_key,
            hybrid_pub,
            inner: Mutex::new(Some(kx)),
        })
    }

    fn take_inner(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        self.inner
            .lock()
            .map_err(|_| Error::General("utls-engine: 密钥交换的锁中毒了".into()))?
            .take()
            .ok_or_else(|| Error::General("utls-engine: 这个密钥交换已经被用过了".into()))
    }
}

impl ExternalKeyExchange for RustlsKx {
    fn group(&self) -> u16 {
        self.group
    }

    fn pub_key(&self) -> Vec<u8> {
        self.pub_key.clone()
    }

    fn hybrid_component(&self) -> Option<(u16, Vec<u8>)> {
        self.hybrid_pub.clone()
    }

    fn complete(&self, peer_pub_key: &[u8]) -> Result<Vec<u8>, Error> {
        let inner = self.take_inner()?;
        Ok(inner.complete(peer_pub_key)?.secret_bytes().to_vec())
    }

    fn complete_hybrid_component(&self, peer_pub_key: &[u8]) -> Result<Vec<u8>, Error> {
        let inner = self.take_inner()?;
        Ok(inner
            .complete_hybrid_component(peer_pub_key)?
            .secret_bytes()
            .to_vec())
    }
}

/// 一次连接的指纹供应者：`spec` 是声明，其余是这次连接的外部输入。
///
/// `record` 是我们**自己**记下发出去的字节的地方：fork 没有「把上次发的 ClientHello
/// 还给我」这种接口，而对账需要那串字节，所以在产出它的地方顺手留一份。
/// 「引擎有没有原样使用它」由另一个更强的判据保证：服务器看到的 JA3 必须与这份字节
/// 算出来的 JA3 一致（见 `examples/handshake.rs`）。
#[derive(Debug)]
pub struct FingerprintClient {
    spec: ClientHelloSpec,
    provider: Arc<CryptoProvider>,
    sni: Option<String>,
    alpn: Vec<Vec<u8>>,
    record: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
    /// 内层 hello 的**密封形态**（可压缩扩展已收进 `0xfd00`，含末尾补零）。
    ///
    /// 与 `record` 同一个理由，只是对象换成「服务器解开密文之后看到的那串字节」：
    /// ECH 的接受那一半（`questions/10`）要拿它与 **uTLS 自己的解码器**
    /// （`decodeInnerClientHello`）对账 —— 而那个解码器只吃这串字节。
    ech_inner_record: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
    /// 钉死的客户端随机数（uTLS 的 `SetClientRandom`）。`None` ⇒ 走 OS 熵。
    client_random: Option<[u8; 32]>,
    /// 服务器的 `ECHConfigList`：给了它，引擎就**自己**构造那份 offer（`with_ech`）。
    ech_config: Option<Vec<u8>>,
    /// 一次**真的** ECH 提议：`(ECHConfigList 原始字节, 内层 ClientHello 的体)`。
    ///
    /// 引擎在这里只是**转交**：外层 hello（含密封好的 `0xfe0d` 扩展）与内层 hello 都是
    /// 调用方给的 —— 因为密封要用 HPKE 上下文，而 AAD 是外层自己的字节（见 `ech.rs`）。
    /// 于是这个开关做的唯一一件事是：让 fork 把 `0xfe0d` 当成**真提议**而不是 GREASE
    /// （`EchStatus::Offered`），并把内层转录/内层随机数交给 rustls —— 服务器接受时
    /// 用的是它们，不是外层的。
    ech_offer: Option<(Vec<u8>, Vec<u8>)>,
    /// **上一飞的输入**。第二飞必须复用同一份（RFC 8446 §4.1.2 只允许改
    /// key_share / cookie / PSK / padding，客户端随机数与 GREASE、乱序都不许变），
    /// 而 fork 的 seam 是**每连接**的，所以这份状态放在这里 —— 与「每连接一次密钥交换」
    /// 同一个理由。
    ///
    /// `Mutex` 而非 `RefCell`：seam 要求 `Send + Sync`（`ClientConfig` 是共享的）。
    last_inputs: Mutex<Option<HandshakeInputs>>,
}

impl FingerprintClient {
    pub fn new(spec: ClientHelloSpec, provider: Arc<CryptoProvider>) -> Self {
        FingerprintClient {
            spec,
            provider,
            sni: None,
            alpn: Vec::new(),
            record: None,
            ech_inner_record: None,
            client_random: None,
            ech_config: None,
            ech_offer: None,
            last_inputs: Mutex::new(None),
        }
    }

    /// 声明「这条连接真的在提议 ECH」，并**由引擎构造**那份 offer。
    ///
    /// `config_list` 是服务器的 `ECHConfigList`（原始字节）。引擎会：
    ///
    /// 1. 解析并挑一条能用的配置（`utls::hello::parse_ech_config_list` / `pick_ech_config`）；
    /// 2. 按五条规则造**内层** hello（见 `ech::build_inner_client_hello_body`）；
    /// 3. 用 `EchSealer` 把它封给配置里的公钥；
    /// 4. 在**外层** hello 的 `0xfe0d` 里写上 `outer_ech_extension_body`：
    ///    先按「等长全零载荷」序列化一遍（那份字节就是 AAD），算出真载荷后
    ///    **原地替换**那一段 —— 长度不变，其余字节一个都不动；
    /// 5. 把 `EchOffer { config_list, inner_client_hello_body }` 交给引擎侧。
    ///
    /// ⚠️ spec 里**不要再自己塞** `0xfe0d`：外层那条由这里写（载荷是算出来的，
    /// 不是指纹的一部分）。内层那份 `[1]` 形态也只出现在内层。
    ///
    /// ⚠️ 语义是**要求 ECH**（rustls 的 `EchMode::Enable`）：服务器不接受就会终止握手，
    /// 不会静默退回公开名字那条路。
    pub fn with_ech(mut self, config_list: Vec<u8>) -> Self {
        self.ech_config = Some(config_list);
        self
    }

    /// 声明「这条连接真的在提议 ECH」。
    ///
    /// `config_list` 是构造这次提议用的 `ECHConfigList`（原始字节），
    /// `inner_client_hello` 是**内层** ClientHello（完整握手消息）；
    /// 而 spec 里必须已经有一条 `0xfe0d` 扩展（外层的那条，载荷已密封）——
    /// 用 [`Extension::Opaque`] 写它即可，因为载荷是引擎算的、不是指纹的一部分。
    ///
    /// ⚠️ 引擎**不生成**这两样，它只转交：密封需要 HPKE 上下文，而 AAD 是外层 hello
    /// 自己的字节（`tls ech\0 || 配置` 当 info、外层编码当 aad —— 见 `ech.rs` 的模块头）。
    /// 生成那条外层的接线（内层的形状有五条规范细节：去掉 EMS/session_ticket/ec_point_formats、
    /// 内层带自己的 ECH 形态、按压缩规则整理……）是下一步，见 STATE.md 的已知缺口。
    pub fn with_ech_offer(mut self, config_list: Vec<u8>, inner_client_hello: Vec<u8>) -> Self {
        self.ech_offer = Some((config_list, inner_client_hello));
        self
    }

    /// uTLS 的 `SetClientRandom`：把这条 ClientHello 的 32 字节随机数**钉死**。
    ///
    /// 用途与 uTLS 一致 —— 录制与对账（uTLS 自己的 `-setclienthello` 夹具就是这么来的）。
    /// 它**不影响**指纹的每连接变化（GREASE / 乱序 / 填充仍走各自那条流）：
    /// 那两件事在本层是刻意分开的，混在一起会让「可复现」与「不可预测」互相污染。
    pub fn with_client_random(mut self, random: [u8; 32]) -> Self {
        self.client_random = Some(random);
        self
    }

    pub fn with_sni(mut self, sni: impl Into<String>) -> Self {
        self.sni = Some(sni.into());
        self
    }

    pub fn with_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = alpn;
        self
    }

    pub fn with_record(mut self, sink: Arc<Mutex<Vec<Vec<u8>>>>) -> Self {
        self.record = Some(sink);
        self
    }

    /// 与 [`Self::with_record`] 同一件事，对象是**内层** hello 的密封形态
    /// （含末尾补零，即服务器解出来的那串字节）。见字段说明。
    pub fn with_ech_inner_record(mut self, sink: Arc<Mutex<Vec<Vec<u8>>>>) -> Self {
        self.ech_inner_record = Some(sink);
        self
    }

    /// spec 里 `key_share` 要求的非 GREASE 组，按声明顺序。
    fn keyshare_groups(&self) -> Vec<u16> {
        // 口径只有一处：指纹层的 `ClientHelloSpec::key_share_groups`。
        // 这里曾经自己数一遍（还有另外 4 处也各数一遍），于是 `key_share` 的模型一改
        // 就会各错各的 —— 那次是 `KeyShare::reuse` 加进来时被编译器抓出来的。
        self.spec.key_share_groups()
    }

    /// 每连接的输入。`os()` 同时给客户端随机数与指纹的每连接变化；
    /// `with_client_random` 只覆盖前者（与 uTLS 的 `SetClientRandom` 同义）。
    fn fresh_inputs(&self) -> HandshakeInputs {
        let mut inputs = HandshakeInputs::os();
        if let Some(r) = self.client_random {
            inputs.client_random = r;
        }
        inputs.sni = self.sni.clone();
        inputs.alpn = self.alpn.clone();
        inputs
    }

    /// 把一条已序列化的 ClientHello 记进记录槽（如果调用方要了记录）。
    fn record(&self, bytes: &[u8]) -> Result<(), Error> {
        if let Some(sink) = &self.record {
            sink.lock()
                .map_err(|_| Error::General("utls-engine: 记录槽的锁中毒了".into()))?
                .push(bytes.to_vec());
        }
        Ok(())
    }

    /// 把会话的 identity 写进 spec 的 PSK 槽位，binder 留**全零占位**。
    ///
    /// 第一飞与第二飞都走它：RFC 8446 §4.2.11.2 要求 HRR 之后重算 binder，
    /// 而 identity（ticket 与混淆年龄）**不变** —— 年龄相对的是「取到会话的那一刻」，
    /// 那件事只发生一次。所以两飞填进去的东西逐字节相同。
    fn fill_psk_slot(
        &self,
        spec: &mut ClientHelloSpec,
        offer: &ResumptionOffer,
    ) -> Result<(), Error> {
        let at = spec.psk_position().ok_or_else(|| {
            Error::General(
                "utls-engine: 这次连接有会话可以复用，但 spec 里没有 pre_shared_key 槽位 —— \
                 uTLS 里对应的开关是 Config.AlwaysIncludePSK（本仓是 \
                 `ClientHelloSpec::always_add_psk`）。**不默认补上**：补一条扩展会改指纹，\
                 而「改指纹」必须由调用方显式要求"
                    .into(),
            )
        })?;
        spec.extensions[at] = Extension::PreSharedKey(PreSharedKey::placeholder(
            vec![PskIdentity {
                label: offer.ticket.clone(),
                obfuscated_ticket_age: offer.obfuscated_ticket_age,
            }],
            offer.binder_len,
        ));
        Ok(())
    }

    /// 造一次 ECH 提议要用的中间物：内层体、密封上下文、外层扩展体（零载荷）。
    ///
    /// 单独抽出来是因为它有**顺序**要求：内层先定型 → 载荷长度才知道 →
    /// 外层里先写等长全零载荷 → 那份外层字节当 AAD → 密封 → 原地替换载荷。
    fn prepare_ech(
        &self,
        spec: &ClientHelloSpec,
        inputs: &HandshakeInputs,
        config_list: &[u8],
    ) -> Result<PreparedEch, Error> {
        let list = parse_ech_config_list(config_list)
            .map_err(|e| Error::General(format!("utls-engine: ECHConfigList 解析失败：{e}")))?;
        let config = pick_ech_config(&list).ok_or_else(|| {
            Error::General(
                "utls-engine: 这份 ECHConfigList 里没有一条我们能用的配置 \
                 （版本/公钥长度/套件/强制扩展任一条不过）"
                    .into(),
            )
        })?;
        let sealer = ech::EchSealer::new(config, &self.provider)?;
        let public_name = core::str::from_utf8(&config.public_name)
            .map_err(|_| Error::General("utls-engine: 配置里的 public_name 不是 UTF-8".into()))?
            .to_string();

        // 外层先按「空载荷」序列化一遍 —— 只为拿到**扩展的线序**。
        //
        // 内层的 marker 要按外层线序排（服务器沿外层做单调查找），而外层的顺序在
        // 乱序预设（Chrome 106+）下是**每连接**定的，只能从序列化结果里读。
        // 扩展的**序列**与那条 `0xfe0d` 的载荷长度无关（载荷只改一个体的长度），
        // 所以这一遍的顺序就是最终外层的顺序；这遍字节本身不外发。
        let mut order_spec = spec.clone();
        put_or_replace_ech_ext(
            &mut order_spec,
            ech::outer_ech_extension_body(
                sealer.cipher_suite(),
                sealer.config_id(),
                sealer.encapsulated_key(),
                &[],
            ),
        );
        let mut order_inputs = inputs.clone();
        order_inputs.sni = Some(public_name.clone());
        let order_bytes = order_spec
            .marshal(&order_inputs)
            .map_err(|e| Error::General(format!("utls-engine: 外层 hello 序列化失败：{e}")))?
            .into_bytes();
        let outer_ext_order = extension_types_of(&order_bytes);

        // 内层：uTLS 的模型 —— **诚实的 hello**（引擎的套件/版本/ALPN），只把
        // keyShares / 曲线 / 签名算法 / session id 从预设抄进去（后者不进密文）。
        let inner = ech::build_inner_client_hello_body(
            spec,
            inputs,
            &ech::InnerHelloInputs {
                sni: inputs.sni.as_deref(),
                alpn: &inputs.alpn,
                cipher_suites: &self.honest_tls13_cipher_suites(),
                outer_ext_order: &outer_ext_order,
                maximum_name_length: config.maximum_name_length,
                resuming: spec.psk_position().is_some(),
            },
        )?;
        let payload_len = sealer.payload_len(inner.sealed.len() + inner.pad)?;
        let outer_body_zeros = ech::outer_ech_extension_body(
            sealer.cipher_suite(),
            sealer.config_id(),
            sealer.encapsulated_key(),
            &vec![0u8; payload_len],
        );

        Ok(PreparedEch {
            sealer,
            public_name,
            inner,
            payload_len,
            outer_body_zeros,
            // 内层随机数**另取一个**：ECH 被接受时进密钥调度的是它，不是外层的。
            outer_random: inputs.client_random,
        })
    }

    /// 引擎**诚实**会报的 TLS 1.3 套件（内层用的是它，不是浏览器的假清单）。
    ///
    /// uTLS 的内层取的是 `config.cipherSuites()` —— 即「这个客户端真正能谈的套件」，
    /// 而**不是**预设里那 17 条摆样子的（内层是服务器接下来真要谈的那条 hello，
    /// 报一条引擎完不成的套件，服务器选中它就握手失败）。
    fn honest_tls13_cipher_suites(&self) -> Vec<u16> {
        self.provider
            .cipher_suites
            .iter()
            .filter(|s| s.tls13().is_some())
            .map(|s| u16::from(s.suite()))
            .collect()
    }

    /// 把 spec 的 `key_share` 里的 **GREASE 项**去掉（只在 ECH 路径上做）。
    ///
    /// # 为什么（这是逐变量实测出来的，见 `questions/10` 的二分记录）
    ///
    /// Chrome-70 那一代的指纹在 `key_share` 里**第一个**放 `{GREASE, [0]}`（真组的
    /// keyshare 跟在后面）。ECH 的服务器会**重建内层**：被压缩进 `0xfd00` 的扩展
    /// （`key_share` 在其中）由服务器拿**外层**的真身填回去 —— 于是那个 GREASE
    /// keyshare 就进了内层。实测三个服务器家族对此的态度：
    ///
    /// | 服务器 | 对「内层里有 GREASE keyshare」 |
    /// |---|---|
    /// | Go 系（uTLS 自带服务端、Cloudflare） | 接受 |
    /// | rustls 自带客户端打这些服务器 | ——（rustls 的 keyshare 里本来就没有 GREASE） |
    /// | **OpenSSL 系（DEfO：defo.ie / test.defo.ie）** | **`illegal_parameter`** |
    ///
    /// 而真实世界里带 ECH 的客户端（Chrome 117+ / Firefox）**本来就不发** GREASE
    /// keyshare —— 那是 Chrome-70 时代的摆设，Chrome 自己上 ECH 时已经不带了。
    /// 所以「ECH 时去掉它」不是妥协，而是与真实 ECH 客户端对齐；
    /// 非 ECH 连接的指纹**一字节都不动**（那条 GREASE keyshare 照发）。
    fn scrub_grease_key_share(&self, spec: &mut ClientHelloSpec) {
        for e in &mut spec.extensions {
            if let Extension::KeyShare(ks) = e {
                ks.groups.retain(|c| !matches!(c, CodePoint::Grease));
            }
        }
    }

    /// 为 `groups` 里引擎能完成的那些组各起一次密钥交换（每连接一次）。
    fn start_exchanges(&self, groups: &[u16]) -> Result<Vec<(u16, RustlsKx)>, Error> {
        let mut out = Vec::new();
        for g in groups {
            out.push((*g, RustlsKx::start(*g, &self.provider)?));
        }
        Ok(out)
    }
}

impl SuppliesClientHello for FingerprintClient {
    fn plan(&self, request: &PlanRequest) -> Result<ClientHelloPlan, Error> {
        let engine_groups = &request.groups;
        // ① 为 spec 要的、且引擎能完成的每个组生成密钥交换。
        //    **每连接一次** —— 复用私钥是缺陷不是特性。
        let want = self.keyshare_groups();
        let usable: Vec<u16> = want
            .iter()
            .copied()
            .filter(|g| engine_groups.contains(g))
            .collect();
        if usable.is_empty() && !want.is_empty() {
            return Err(Error::General(format!(
                "utls-engine: spec 的 key_share 组 {want:?} 与引擎能完成的组 {engine_groups:?} \
                 没有交集 —— 这样发出去的 ClientHello 永远握不上手"
            )));
        }
        // ⚠️ `want` **空** 是另一回事：那是 TLS 1.2 时代的指纹（Chrome 58 / Firefox 55 /
        // iOS 11 / Android 11 / 360 7…），它们的 spec 里**根本没有 `key_share` 扩展**。
        // 这种 hello 走 TLS 1.2，ECDHE 在第二飞（`ClientKeyExchange`）里由引擎自己做，
        // 所以「没有外部交换」不是缺陷，是这一档的正常形态。原来的代码把它与
        // 「声明了组但一个都完不成」混为一谈，于是这 8 档连字节都发不出去。
        let mut exchanges = self.start_exchanges(&usable)?;

        // ①′ 混合组与经典组**共用同一份密钥材料**（uTLS 的
        // `ReuseHybridAndClassicalKeyShares`，`u_public.go:656`）。
        //
        // 为什么要有这条：真实 Firefox 只生成一把 X25519 密钥，混合组公钥的末 32 字节
        // 就是它的经典组公钥。uTLS 复刻了这个关系，并且有一条专门的判据
        // （`u_parrots_test.go:63`）。本仓的 `Firefox(148)` 预设声明它
        // （`ClientHelloSpec::key_share_reuse`），**只有它**声明 ——
        // Chrome 131 那种 `[GREASE, 4588, X25519]` 发的不是同一份材料，所以
        // 顺带按「报了混合组也报了它的经典分量」来推断是错的，必须由声明驱动。
        //
        // 接法：**只交一把**（混合组那把）给引擎，经典条目的公钥取它的
        // `hybrid_component()`。这样
        //   * 线上两个条目的末 32 字节相同（＝ Firefox 的样子）；
        //   * 服务器选中经典组时，fork 的 `OfferedKeyShares::take_for` 按
        //     「组或它的 hybrid 分量」匹配到同一把交换（`rustls/src/client/hs.rs:83-92`），
        //     再走 `complete_hybrid_component` 得到 X25519 的共享密钥（`client/tls13.rs:277-310`）
        //     —— 与线上那半公钥一致。
        // 这正是 rustls 自己那条「第二条 key_share 白送」的路径
        // （`client/hs.rs:505-533`）用的机制，只是那边由引擎自建、这边由指纹层声明。
        let mut reused_component: Option<(u16, Vec<u8>)> = None;
        if let Some((hybrid, classical)) = self.spec.key_share_reuse() {
            let component = exchanges
                .iter()
                .find(|(g, _)| *g == hybrid)
                .and_then(|(_, kx)| kx.hybrid_component())
                .filter(|(cg, _)| *cg == classical);
            match component {
                Some((cg, key)) if want.contains(&classical) => {
                    // 独立那把不再需要：经典条目用的就是混合组那一把的经典分量。
                    exchanges.retain(|(g, _)| *g != classical);
                    reused_component = Some((cg, key));
                }
                // 声明了却做不到 ⇒ **响亮失败**。发一条「声称共用、实则各用各的」hello
                // 是**假保真**：字节形状一样，而 Firefox 会做的事我们没做。
                // （这条只在提供者不提供该混合组、或它不上报经典分量时才可能发生。）
                _ => {
                    return Err(Error::General(format!(
                        "utls-engine: spec 声明了组 0x{hybrid:04x} 与 0x{classical:04x} 共用\
                         密钥材料（uTLS 的 ReuseHybridAndClassicalKeyShares），但这个提供者\
                         建不出那份混合交换（或不上报它的经典分量）—— 与其发一条与 Firefox \
                         不同的 hello，不如在这里失败"
                    )));
                }
            }
        }

        // ② 会话复用：引擎把会话当**数据**交给我们（ticket / 混淆年龄 / binder 长度），
        //    我们填进 spec 的 PSK 槽位、binder 留**占位零字节**；真 binder 由引擎在
        //    拿到字节之后算（它才持有会话密钥），见 `ClientHelloPlan::psk_binder`。
        let (spec, psk_binder) = match &request.resumption {
            Some(offer) => {
                let mut spec = self.spec.clone();
                self.fill_psk_slot(&mut spec, offer)?;
                (spec, true)
            }
            None => (self.spec.clone(), false),
        };

        // ③ 每连接的输入。公钥**长度**进指纹（它决定总长，进而决定要不要填充），
        //    所以 spec 里出现的**每一个**非 GREASE 组都要给公钥 —— 包括引擎完不成的那些。
        //
        //    为什么完不成的组也要给：Chrome 的 PQ 预设（`ChromePq(115)`/`(120)`、`ChromePsk(115)`）
        //    的 `key_share` 是 `[GREASE, X25519Kyber768Draft00(0x6399), X25519]`。
        //    `0x6399` 是**草案**组，rustls 的 aws-lc-rs 提供者只有 `X25519MLKEM768(4588)`
        //    —— 于是这一档的「形状」根本发不出去（编码器要它 1216 字节的公钥）。
        //    但我们**只需要发对形状**：给 `0x6399` 一个长度正确的占位公钥
        //    （长度表在指纹层：`values::group_public_key_len`，它认得这个草案组），
        //    真交换只交可完成的那些（这里是 X25519）。后果如实说清：
        //    * 服务器**不认** `0x6399` ⇒ 它选 X25519 ⇒ 握手照常完成 ✓
        //      （这也正是真实世界的情形：不认这个草案组的服务器就回退到 X25519）；
        //    * 服务器**认** `0x6399` 并选了它 ⇒ 我们完成不了，fork 会**响亮报错**
        //      （`OfferedKeyShares::take_for` 找不到对应交换），不会静默降级成别的组。
        //      这是与 uTLS 的**语义**差异（uTLS 自己实现了这个草案组，能完成）——
        //      我们选择「形状逐字节像 Chrome，完成不了就明说」，而不是「拒绝整档预设」。
        //
        //    占位字节取**密码学随机**（不是常量）：真公钥看起来就是随机字节，
        //    用常量会让两连接的可比字节里多出一个固定模式。
        let mut inputs = self.fresh_inputs();
        inputs.key_exchange = want
            .iter()
            .map(|g| {
                // 共用的那一半：经典条目的公钥**就是**混合组的经典分量（见 ①′）。
                // 少了这一步，线上两个条目会各用各的材料 —— 形状一样、关系不同。
                if let Some((cg, key)) = &reused_component
                    && cg == g
                {
                    return Ok((*g, key.clone()));
                }
                match exchanges.iter().find(|(eg, _)| eg == g) {
                    Some((_, kx)) => Ok((*g, kx.pub_key())),
                    None => {
                        let len = v::group_public_key_len(*g).ok_or_else(|| {
                            Error::General(format!(
                                "utls-engine: 组 0x{g:04x} 在 spec 的 key_share 里，但指纹层不知道\
                             它的公钥长度 —— 发不出一条形状正确的 hello"
                            ))
                        })?;
                        let mut placeholder = vec![0u8; len];
                        self.provider.secure_random.fill(&mut placeholder)?;
                        Ok((*g, placeholder))
                    }
                }
            })
            .collect::<Result<Vec<_>, Error>>()?;
        *self
            .last_inputs
            .lock()
            .map_err(|_| Error::General("utls-engine: 输入槽的锁中毒了".into()))? =
            Some(inputs.clone());

        // ③′ ECH：有配置就**自己**造那条 offer —— 内层按 uTLS 的「诚实 hello」模型，
        //     外层写密封载荷。顺序不能换：载荷长度要先知道（外层里得先放等长全零载荷），
        //     而 AAD 就是「载荷为零」的那份外层字节。
        let ech = match &self.ech_config {
            Some(config_list) => {
                // **ECH 时外层不带 GREASE key share**（理由与出处见
                // [`FingerprintClient::scrub_grease_key_share`]）。
                // 只影响 ECH 这条连接的外层；非 ECH 路径的 spec 原样。
                let mut spec = spec.clone();
                self.scrub_grease_key_share(&mut spec);
                let mut prepared = self.prepare_ech(&spec, &inputs, config_list)?;
                inputs.client_random = prepared.outer_random;
                // 外层：spec 里放上 `0xfe0d`（等长全零载荷），SNI 换成公开名。
                // ⚠️ 新预设（Chrome 133+ / Firefox 120+）自带一条 GREASE 形态的
                // `0xfe0d`（`Extension::GreaseEch`）—— 真 ECH 模式下要**替换**它，
                // 不是再叠一条（marshaller 会因扩展类型重复而拒绝）。
                let mut outer_spec = spec;
                put_or_replace_ech_ext(&mut outer_spec, prepared.outer_body_zeros.clone());
                let mut outer_inputs = inputs.clone();
                outer_inputs.sni = Some(prepared.public_name.clone());
                let outer = outer_spec
                    .marshal(&outer_inputs)
                    .map_err(|e| {
                        Error::General(format!("utls-engine: 外层 hello 序列化失败：{e}"))
                    })?
                    .into_bytes();
                let sealed = patch_ech_payload(outer, &mut prepared)?;
                if let Some(sink) = &self.ech_inner_record {
                    let mut plaintext = prepared.inner.sealed.clone();
                    plaintext.extend(std::iter::repeat_n(0, prepared.inner.pad));
                    // 两条：①**密封形态**（服务器解开密文看到的那串字节）；
                    // ②**转录形态**（可压缩扩展展开回来 —— 服务器重建之后按它算转录，
                    //   而「重建得一样不一样」正是 `ech_status = Rejected` 那一半的判据）。
                    let mut guard = sink
                        .lock()
                        .map_err(|_| Error::General("utls-engine: 内层记录槽的锁中毒了".into()))?;
                    guard.push(plaintext);
                    guard.push(prepared.inner.expanded.clone());
                }
                Some((sealed, config_list.clone(), prepared.inner.expanded))
            }
            None => None,
        };

        let (bytes, ech_offer) = match ech {
            Some((outer, list, inner_body)) => (
                outer,
                Some(EchOffer {
                    config_list: list,
                    inner_client_hello: inner_body,
                }),
            ),
            None => (
                spec.marshal(&inputs)
                    .map_err(|e| {
                        Error::General(format!("utls-engine: 指纹层拒绝产出 ClientHello：{e}"))
                    })?
                    .into_bytes(),
                None,
            ),
        };

        // ④ 告诉引擎 binder 该写在哪（RFC 8446 §4.2.11.2 的截断点）。
        let psk_binder = if psk_binder {
            let truncated_len = hello_psk_transcript_len(&bytes)?;
            Some(PskBinderSlot {
                truncated_len,
                binder_len: request
                    .resumption
                    .as_ref()
                    .map(|r| r.binder_len)
                    .unwrap_or_default(),
            })
        } else {
            None
        };
        let sent = extension_types_of(&bytes);
        self.record(&bytes)?;

        // 把**每一把**交换都交给引擎：`key_share` 里有几个组，就交几把。
        //
        // 曾经这里只交第一把，而后果是：服务器**选中我们声明过的另一个组**时握手直接失败
        // （`WrongGroupForKeyShare`）—— 那不是策略，是缺陷（uTLS 把每个组的公钥都发出去，
        // 服务器选哪个都能接着谈）。
        let exchanges: Vec<Arc<dyn ExternalKeyExchange>> = exchanges
            .into_iter()
            .map(|(_, kx)| Arc::new(kx) as Arc<dyn ExternalKeyExchange>)
            .collect();
        if exchanges.is_empty() && !want.is_empty() {
            // `want` 非空却一把交换都没有 = 内部不一致（上面刚按它筛过）。
            // `want` **空**（spec 里没有 `key_share` —— TLS 1.2 时代那几档）不是错误：
            // 那几档的第二飞由引擎自己做 ECDHE，第一飞本来就不该带交换。
            return Err(Error::General("utls-engine: 内部错误，密钥交换为空".into()));
        }

        Ok(ClientHelloPlan {
            client_hello: Some(bytes),
            sent_extensions: Some(sent),
            key_exchanges: exchanges,
            psk_binder,
            // 优先级：自己造的那份（`with_ech`）> 调用方交的那份（`with_ech_offer`）> `None`。
            // `None` 意味着「这条 hello 里的 0xfe0d 是 GREASE」，那正是 fingerprint 层
            // `Extension::GreaseEch` 的用途。
            ech: ech_offer.or_else(|| {
                self.ech_offer.as_ref().map(|(list, inner)| EchOffer {
                    config_list: list.clone(),
                    inner_client_hello: inner.clone(),
                })
            }),
            // 下面三项只影响「引擎自己构建 ClientHello」的那条路 —— 我们外供了字节，
            // 所以它们是惰性的。仍然按 spec 的意图填，免得以后有人切回引擎自建时莫名其妙。
            stable_extension_order: spec.variability == Variability::Stable,
            extra_cipher_suites: Vec::new(),
            suppress_renegotiation_scsv: true,
        })
    }

    /// 第二飞（HRR 的回复）。
    ///
    /// 与第一飞的唯一区别是**输入必须复用**：客户端随机数、GREASE、乱序、session id
    /// 全部照搬（RFC 8446 §4.1.2 只允许改 key_share / cookie / PSK / padding），
    /// 所以这里从 `last_inputs` 取那份输入，只把 `key_exchange` 换成新组的公钥。
    fn retry_plan(&self, req: &HelloRetryRequestPlan) -> Result<ClientHelloPlan, Error> {
        let stored = self
            .last_inputs
            .lock()
            .map_err(|_| Error::General("utls-engine: 输入槽的锁中毒了".into()))?
            .clone()
            .ok_or_else(|| {
                Error::General(
                    "utls-engine: 引擎在没调用过 plan() 的情况下要第二飞 —— \
                     没有第一飞的输入可复用，而 RFC 8446 §4.1.2 要求复用"
                        .into(),
                )
            })?;

        // ① spec：key_share 只留服务器选中的那个组（`for_hello_retry`），
        //    再按需把 cookie 插进去。
        let mut spec = self.spec.clone();
        if let Some(group) = req.selected_group {
            spec = spec
                .for_hello_retry(group)
                .map_err(|e| Error::General(format!("utls-engine: 指纹层不接受这次 HRR：{e}")))?;
        }
        if let Some(cookie) = &req.cookie {
            // uTLS 从一条**独立的** OS 熵流里抽 `Intn(len - 2)`（即 `[0, len-3]`），
            // 所以它自己的 cookie 位置也不可复现。我们取那个区间的**上界**
            // （`len - 3`）：分布仍在 uTLS 可能的取值里，但行为可复现 ——
            // 而且从连接流里抽会多消耗随机数，把 GREASE 与乱序推离第一飞（RFC 不允许）。
            let n = spec.extensions.len();
            let index = n.saturating_sub(3);
            spec = spec
                .with_cookie(cookie, index)
                .map_err(|e| Error::General(format!("utls-engine: cookie 插不进去：{e}")))?;
        }

        // ② 新组的密钥交换（只有 HRR 选了组才需要）。
        let mut inputs = stored;
        let mut kx: Option<Arc<dyn ExternalKeyExchange>> = None;
        if let Some(group) = req.selected_group {
            let started = RustlsKx::start(group, &self.provider)?;
            inputs.key_exchange = vec![(group, started.pub_key())];
            kx = Some(Arc::new(started));
        }

        // ③ PSK：HRR **不**作废会话，binder 要在新转录上**重算**
        //    （RFC 8446 §4.2.11.2；uTLS 的 `UpdateOnHRR`）。identity 与年龄原样复用。
        if let Some(offer) = &req.resumption {
            self.fill_psk_slot(&mut spec, offer)?;
        }

        let bytes = spec
            .marshal(&inputs)
            .map_err(|e| Error::General(format!("utls-engine: 指纹层拒绝产出第二飞：{e}")))?
            .into_bytes();
        let sent = extension_types_of(&bytes);
        self.record(&bytes)?;

        // ④ 第二飞的截断点与第一飞**不同**（转录多了 message_hash||HRR 的字节，
        //    而这条 hello 本身也可能更长/更短），所以必须重新算一遍，不能复用第一飞那个。
        let psk_binder = match &req.resumption {
            Some(offer) => Some(PskBinderSlot {
                truncated_len: hello_psk_transcript_len(&bytes)?,
                binder_len: offer.binder_len,
            }),
            None => None,
        };

        Ok(ClientHelloPlan {
            client_hello: Some(bytes),
            sent_extensions: Some(sent),
            psk_binder,
            ech: None,
            // cookie-only 的 HRR 不改 key_share ⇒ 空列表，引擎继续用第一飞那把交换。
            key_exchanges: kx.into_iter().collect(),
            stable_extension_order: spec.variability == Variability::Stable,
            extra_cipher_suites: Vec::new(),
            suppress_renegotiation_scsv: true,
        })
    }
}

/// ECH 提议的中间物（见 `FingerprintClient::prepare_ech`）。
struct PreparedEch {
    sealer: ech::EchSealer,
    public_name: String,
    /// 内层的两种形态（加密用的带标记；转录用的展开）。
    inner: ech::InnerHellos,
    payload_len: usize,
    /// 外层 `0xfe0d` 的体，载荷段是等长全零 —— 这一份字节同时决定 AAD。
    outer_body_zeros: Vec<u8>,
    outer_random: [u8; 32],
}

/// 把密封好的载荷**原地**写进外层 hello（长度不变）。
///
/// 这是整个仓库里第二处「对已序列化消息做字节改写」（第一处是 PSK binder），
/// 成立的理由相同：**只改载荷、不改任何长度**。所以：
/// 长度字段、外层字节当 AAD 的那份编码、以及引擎从外带字节里学到的状态全都不受影响。
fn patch_ech_payload(mut outer: Vec<u8>, p: &mut PreparedEch) -> Result<Vec<u8>, Error> {
    // 载荷段就是「零载荷外层扩展体」的尾巴；用整段体去定位，错不了的（体里有 32 字节随机封装密钥）。
    let at = outer
        .windows(p.outer_body_zeros.len())
        .rposition(|w| w == p.outer_body_zeros.as_slice())
        .ok_or_else(|| Error::General("utls-engine: 外层里找不到刚写进去的 ECH 扩展体".into()))?;
    let payload_at = at + p.outer_body_zeros.len() - p.payload_len;
    // ⚠️ AAD 是外层的 **ClientHello 体**（不含 4 字节握手头）。
    //
    // 这条是拿**能通的参照实现**对出来的：rustls 的 `ech_hello` 把
    // `ClientHelloPayload::get_encoding()` 当 AAD，而那是**体**（`type || u24 || body` 里的
    // body）；本仓第一版给的是**整条握手消息**（含头）—— 4 个字节之差，AEAD 就永远认证不过，
    // 而两边的**本地往返**都自洽（自己封、自己解，用同一个错的 AAD），所以只有真服务器能证伪。
    // （uTLS 那边用的是 `Hello.Raw`，即含头的整条消息 —— 两个参照在这一点上并不一致；
    // 我们跟**在这台机器上实测被接受**的那一个。）
    let aad = outer[4..].to_vec();
    let mut plaintext = p.inner.sealed.clone();
    plaintext.extend(std::iter::repeat_n(0u8, p.inner.pad));
    let sealed = p
        .sealer
        .seal(&aad, &plaintext)
        .map_err(|e| Error::General(format!("utls-engine: HPKE 密封失败：{e}")))?;
    if sealed.len() != p.payload_len {
        return Err(Error::General(format!(
            "utls-engine: 密封结果长 {} 字节，而外层预留了 {} —— 替换会改长度",
            sealed.len(),
            p.payload_len
        )));
    }
    outer[payload_at..payload_at + p.payload_len].copy_from_slice(&sealed);
    Ok(outer)
}

/// 从我们刚序列化出的字节里取 RFC 8446 §4.2.11.2 的截断点。
///
/// `utls` 那边有同一个方法（`ClientHello::psk_transcript_len`），但**这里不能直接用**：
/// 引擎手里只有 `Vec<u8>`（`ClientHelloPlan` 的字段就是字节）。所以这一层薄封装
/// 把字节重新包成 `ClientHello` 再问它 —— 判据仍然只有一份，在指纹层。
fn hello_psk_transcript_len(bytes: &[u8]) -> Result<usize, Error> {
    utls::hello::psk_transcript_len(bytes).ok_or_else(|| {
        Error::General(
            "utls-engine: 我们刚写出去的 ClientHello 里找不到 pre_shared_key 的截断点 —— \
                 填了 PSK 却没写出去"
                .into(),
        )
    })
}

/// 从线字节里读出全部扩展类型（含引擎不认识的）。fork 需要它做「服务器回了我们没提供的
/// 扩展」这项检查 —— 引擎自己的解码器会把未知类型丢掉，所以那份清单必须由写字节的一方给。
fn extension_types_of(hello: &[u8]) -> Vec<u16> {
    let len = ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | hello[3] as usize;
    let body = &hello[4..4 + len];
    let mut p = 2 + 32;
    p += 1 + body[p] as usize;
    let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + body[p] as usize;
    let exts = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let region = &body[p..p + exts];
    let mut out = Vec::new();
    let mut q = 0usize;
    while q + 4 <= region.len() {
        out.push(u16::from_be_bytes([region[q], region[q + 1]]));
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        q += 4 + bl;
    }
    out
}

/// 把 `0xfe0d`（外层 ECH 扩展，体由调用方给）放进 spec —— 已有（GREASE 形态或
/// 上次留的）就**原地替换**，没有才追加。
///
/// 为什么不能无脑 push：Chrome 133+ / Firefox 120+ 的预设自带一条 GREASE 形态的
/// `0xfe0d`（`Extension::GreaseEch`）， marshaller 对重复的扩展类型会拒绝 —— 而
/// 「真 ECH」模式下那条摆设本来就该被真载荷换掉。
fn put_or_replace_ech_ext(spec: &mut ClientHelloSpec, body: Vec<u8>) {
    match spec
        .extensions
        .iter_mut()
        .find(|e| e.wire_type() == Some(v::EXT_ENCRYPTED_CLIENT_HELLO))
    {
        Some(Extension::Opaque { body: b, .. }) => *b = body,
        Some(e) => {
            *e = Extension::Opaque {
                id: v::EXT_ENCRYPTED_CLIENT_HELLO,
                body,
            };
        }
        None => spec.extensions.push(Extension::Opaque {
            id: v::EXT_ENCRYPTED_CLIENT_HELLO,
            body,
        }),
    }
}

/// 用一份指纹 spec 建 `ClientConfig`。信任锚用 `webpki-roots`（纯数据，不碰系统证书库）。
pub fn client_config(client: FingerprintClient) -> Result<ClientConfig, Error> {
    let provider = client.provider.clone();
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // ALPN 必须与写进 ClientHello 的一致：引擎会拿协商结果跟它比对。
    config.alpn_protocols = client.alpn.clone();
    config.fork_client_hello = Some(Arc::new(client));
    Ok(config)
}

/// 一次真实握手的结果 —— 够用来对账。
pub struct Handshake {
    /// 我们**实际发出去**的那条 ClientHello（逐字节）。
    pub client_hello: Vec<u8>,
    pub negotiated_alpn: Option<Vec<u8>>,
    pub negotiated_version: Option<rustls::ProtocolVersion>,
    pub peer_cert_count: usize,
    /// 服务器是否接受了这次握手（读到过任何应用数据或干净关闭都算读到过）。
    pub reached_server: bool,
}

/// 连 `addr`（形如 `host:port`），用 `host` 做 SNI，跑完一次握手。
///
/// 这是 [`UClient`] 的薄封装 —— 指纹的装配路径只有 `UClient` 一处，避免两条路各自漂。
pub fn connect(
    spec: ClientHelloSpec,
    host: &str,
    addr: &str,
    alpn: Vec<Vec<u8>>,
) -> Result<(Handshake, Vec<u8>), Box<dyn std::error::Error>> {
    let (conn, hello) = UClient::new()
        .apply_preset(spec)
        .set_alpn(alpn)
        .connect(host, addr)?;
    let hs = Handshake {
        client_hello: hello.clone(),
        negotiated_alpn: conn.negotiated_alpn(),
        negotiated_version: conn.negotiated_version(),
        peer_cert_count: conn.peer_certs(),
        // 握手跑通了 ⇒ 服务器收下了那条 ClientHello。真正的「读到东西」由 http_get 那侧判。
        reached_server: true,
    };
    Ok((hs, Vec::new()))
}

/// 握手之后发一个 HTTP/1.1 GET，把响应体读回来（对账端点要的是这个）。
pub fn http_get(
    spec: ClientHelloSpec,
    host: &str,
    addr: &str,
    path: &str,
) -> Result<(Handshake, String), Box<dyn std::error::Error>> {
    let (mut conn, hello) = UClient::new()
        .apply_preset(spec)
        .set_alpn(vec![b"http/1.1".to_vec()])
        .connect(host, addr)?;
    let body = conn.http_get(host, path)?;
    let hs = Handshake {
        client_hello: hello,
        negotiated_alpn: conn.negotiated_alpn(),
        negotiated_version: conn.negotiated_version(),
        peer_cert_count: conn.peer_certs(),
        reached_server: !body.is_empty(),
    };
    Ok((hs, body))
}

// ── uTLS 形状的 API：UClient / UConn / apply_preset ─────────────────────────

/// uTLS 的 `tls.UClient(conn, config, id)` 与 `(*UConn).ApplyPreset(p)` 在这里的等价物。
///
/// # 与 uTLS 的形状差异（**架构差异，不是简化**）
///
/// uTLS 的 `UConn` 是**可变**的：`ApplyPreset` 可以在**建连之后、握手之前**调用。
/// rustls 的连接在创建时就消耗掉 `ClientConfig`，而外供 ClientHello 的接缝挂在 config 上 ——
/// 所以「往一条已经存在的连接上施加预设」在 rustls 的形状里没有位置。
/// 于是这里把「施加预设」挪到**建连之前**：`UClient` 攒好配置，`connect()` 才建连并握手。
///
/// ```no_run
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use utls::hello::ClientHelloId;
/// use utls_engine::UClient;
///
/// let (conn, hello) = UClient::new()
///     .apply_preset_by_id(ClientHelloId::Chrome(133))?   // 对应 ApplyPreset
///     .set_sni("example.com")
///     .set_alpn(vec![b"http/1.1".to_vec()])
///     .connect("example.com", "example.com:443")?;
/// println!("发出 {} 字节，协商版本 {:?}", hello.len(), conn.negotiated_version());
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct UClient {
    spec: ClientHelloSpec,
    sni: Option<String>,
    alpn: Vec<Vec<u8>>,
    provider: Arc<CryptoProvider>,
}

impl UClient {
    /// 默认用 rustls 的 `aws_lc_rs` 提供者。
    pub fn new() -> Self {
        Self::with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
    }

    pub fn with_provider(provider: Arc<CryptoProvider>) -> Self {
        // 起点是一份空 spec（uTLS 的 `HelloCustom`）：`apply_preset` 之前它 marshal 会失败，
        // 那是刻意的 —— 空 spec 不是一条能用的 ClientHello。
        UClient {
            spec: ClientHelloSpec::empty(),
            sni: None,
            alpn: Vec::new(),
            provider,
        }
    }

    /// uTLS 的 `(*UConn).ApplyPreset(p)`。
    ///
    /// uTLS 的注释是「should only be used in conjunction with HelloCustom to apply custom
    /// specs」，并且它**先把 spec 克隆一份**再施加每连接状态。本仓这边 spec 是**按值传入**的
    /// （调用方那份不会被改动）—— 同一个契约，用类型表达而不是用克隆。
    pub fn apply_preset(mut self, spec: ClientHelloSpec) -> Self {
        self.spec = spec;
        self
    }

    /// uTLS 的 `applyPresetByID`：按 ID 取预设再施加。
    ///
    /// 三个随机化 ID 会**现取一个随机种子**（uTLS 在 `Seed == nil` 时就是这么做的），
    /// 所以每次调用产出的指纹不同；`Golang` 返回 [`utls::hello::SpecError::EngineDefined`]
    /// （它的意思是「用引擎自己的 ClientHello」，即不使用本层）。
    pub fn apply_preset_by_id(
        self,
        id: utls::hello::ClientHelloId,
    ) -> Result<Self, utls::hello::SpecError> {
        let spec = if id.is_randomized() {
            ClientHelloSpec::randomized_os(id, &self.alpn)?
        } else {
            ClientHelloSpec::from_preset(id)?
        };
        Ok(self.apply_preset(spec))
    }

    pub fn set_sni(mut self, sni: impl Into<String>) -> Self {
        self.sni = Some(sni.into());
        self
    }

    pub fn set_alpn(mut self, alpn: Vec<Vec<u8>>) -> Self {
        self.alpn = alpn;
        self
    }

    /// 当前要用的 spec（还没建连时也能看）。
    pub fn spec(&self) -> &ClientHelloSpec {
        &self.spec
    }

    /// 建连并跑完握手。返回连接与**实际发出去的**那条 ClientHello 的字节。
    pub fn connect(
        self,
        host: &str,
        addr: &str,
    ) -> Result<(UConn, Vec<u8>), Box<dyn std::error::Error>> {
        let sink: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let client = FingerprintClient::new(self.spec, self.provider)
            .with_sni(host)
            .with_alpn(self.alpn)
            .with_record(sink.clone());
        let config = client_config(client)?;

        let server_name = ServerName::try_from(host.to_string())?;
        let conn = ClientConnection::new(Arc::new(config), server_name)?;
        let tcp = TcpStream::connect(addr)?;
        tcp.set_nodelay(true).ok();
        let mut stream = StreamOwned::new(conn, tcp);

        // **显式把握手跑完**：`complete_io` 只驱动握手，不会吞掉应用数据。
        //
        // ⚠️ 不要用「读一个字节来推动握手」那一招：在阻塞 socket 上它会一直等到服务器
        // 发应用数据 —— 而服务器在等我们的请求，于是整条连接卡死（实测：45 秒后空响应）。
        // 旧版 `http_get` 之所以没踩到，只是因为它「先写请求再读」而已。
        stream.conn.complete_io(&mut stream.sock)?;

        let hello = sink
            .lock()
            .map_err(|_| "记录槽的锁中毒了")?
            .last()
            .cloned()
            .ok_or("指纹层没有产出 ClientHello —— plan() 没被调用？")?;
        Ok((UConn { stream }, hello))
    }
}

impl Default for UClient {
    fn default() -> Self {
        Self::new()
    }
}

/// 一次已握手的连接（uTLS 的 `UConn` 的「连接」那一半）。
#[derive(Debug)]
pub struct UConn {
    stream: StreamOwned<ClientConnection, TcpStream>,
}

impl UConn {
    /// 用**调用方建的** rustls 连接与已连好的 socket 组装一条 `UConn`。
    ///
    /// 为什么需要它：`UClient::connect` 的信任锚固定在 `webpki-roots` 上，而判据常常要
    /// 打**本地**服务端（自签证书）或别的可控端点。有了这个构造器，那些测试与
    /// `Roller` 这类「只关心握手成不成」的部件都能复用同一套 `UConn` 接口，
    /// 而不必各自再写一遍读写与 `http_get`。
    pub fn from_connection(conn: ClientConnection, sock: TcpStream) -> Self {
        sock.set_nodelay(true).ok();
        UConn {
            stream: StreamOwned::new(conn, sock),
        }
    }

    /// 底层连接的只读视图（诊断用：协议版本、ALPN、对端证书条数都从这里取）。
    pub fn connection(&self) -> &ClientConnection {
        &self.stream.conn
    }

    /// 底层 socket（诊断用；也是「握完手之后还能不能继续读写」这类判据的入口）。
    pub fn stream_mut(&mut self) -> &mut StreamOwned<ClientConnection, TcpStream> {
        &mut self.stream
    }

    pub fn negotiated_alpn(&self) -> Option<Vec<u8>> {
        self.stream.conn.alpn_protocol().map(<[u8]>::to_vec)
    }

    pub fn negotiated_version(&self) -> Option<rustls::ProtocolVersion> {
        self.stream.conn.protocol_version()
    }

    pub fn peer_certs(&self) -> usize {
        self.stream
            .conn
            .peer_certificates()
            .map(<[_]>::len)
            .unwrap_or(0)
    }

    pub fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(buf)?;
        self.stream.flush()
    }

    /// 读一段。`Ok(0)` 表示对端关了。
    pub fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }

    /// 发一个 HTTP/1.1 GET 并把响应全文读回来（对账端点用得上）。
    pub fn http_get(&mut self, host: &str, path: &str) -> std::io::Result<String> {
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: utls-rs/0.1\r\n\
             Accept: */*\r\nConnection: close\r\n\r\n"
        );
        self.write_all(req.as_bytes())?;
        let mut body = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match self.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
            }
        }
        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}
