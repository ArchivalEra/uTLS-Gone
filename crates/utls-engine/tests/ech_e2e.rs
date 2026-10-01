//! **真实 ECH 的端到端**：从 DNS 取服务器的 `ECHConfigList`，真握手，断言服务端**接受**了。
//!
//! 这是 ECH 那条路唯一缺的一半。之前所有判据都是「封出去的东西长什么样」
//! （解回载荷逐条验五条规则）与「状态字段有没有被当成真提议」，而**接受**那一步
//! 需要一台真的 ECH 服务器：本地那台 rustls 服务端**没有**服务端 ECH
//! （`rustls` 只实现了客户端），所以只能打公网。
//!
//! # 本机的网络实况（实测，决定了这个测试怎么写）
//!
//! - `crypto.cloudflare.com:443` / `defo.ie:443` **可达**；
//! - `https://cloudflare-dns.com/dns-query`（DoH）**不通** —— 于是「用 DoH 取 ECHConfigList」
//!   那条路走不了；
//! - **普通 DNS（type 65 / HTTPS 记录）通**：`dig +short -t TYPE65 <host> @1.1.1.1` 能取到
//!   `ech=<base64url>` 的 SvcParam。所以配置从 DNS 取，不走 DoH。
//!
//! # 为什么必须有 egress，以及为什么是 `#[ignore]`
//!
//! 与 `end_to_end.rs` 同一类：要真网络。默认不跑，显式开：
//!
//! ```bash
//! cargo test -p utls-engine --test ech_e2e -- --ignored --nocapture
//! ```
//!
//! 依赖 `dig`（`bind9-dnsutils`）与到 `1.1.1.1:53` 的 UDP 通路；缺任何一样，测试会**响亮失败**
//! 并说明缺什么 —— 不静默跳过（那会看起来像通过）。
//!
//! # 现状：**全绿**（三族服务器都接受了我们的提议）
//!
//! 本机实测：`crypto.cloudflare.com`、`defo.ie` 与 `test.defo.ie`（DEfO/OpenSSL 系）都报
//! `EchStatus::Accepted`；对照组（rustls 自带的 ECH 客户端）在同样两个端点上同样被接受。
//! 排查链、被修掉的三处真 bug（AAD、内层转录的 session id、GREASE keyshare）与
//! 「逐变量二分」的记录见 `questions/10-ech-acceptance-falsified.md`（已 resolved）。
//!
//! 判据**没有**放宽：`ech_status == Accepted` 仍是真服务器给出的非此即彼的事实；
//! 想看它红，把 `scrub_grease_key_share` 摘掉再打 DEfO 的端点即可（二分测试就是这么复现的）。
//!
//! # 为什么配置必须**当场取**、不能 vendor 进仓库
//!
//! ECH 配置里带的是服务器的一次性 HPKE 公钥，**会轮换**。vendored 一份等于给测试埋一个
//! 到期炸弹：过期之后失败信息会是「服务器拒绝了我们的提议」，看起来像我们的实现坏了。
//! 当场取、当次用，失败信息就永远指向真因。

use std::process::Command;
use std::sync::Arc;

use rustls::client::EchStatus;
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use utls::hello::{ClientHelloId, ClientHelloSpec, parse_ech_config_list, pick_ech_config};
use utls_engine::FingerprintClient;

/// 从 DNS 的 HTTPS(65) 记录里取 `ech=` SvcParam，base64url 解成 `ECHConfigList` 字节。
///
/// 返回 `Err` 里带上「缺什么」（`dig` 不在？DNS 不通？那个域没有 ECH？），
/// 因为这条链路的每一环都可能断，而失败的形状都一样（拿不到配置）。
fn fetch_ech_config_list(host: &str) -> Result<Vec<u8>, String> {
    let out = Command::new("dig")
        .args(["+short", "-t", "TYPE65", host, "@1.1.1.1"])
        .output()
        .map_err(|e| format!("跑不动 dig（需要 bind9-dnsutils，且 1.1.1.1:53 要通）：{e}"))?;
    if !out.status.success() {
        return Err(format!("dig 退出码 {:?}", out.status.code()));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let ech = text
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("ech="))
        .ok_or_else(|| format!("{host} 的 HTTPS 记录里没有 ech= 参数（原始输出：{text:?}）"))?;
    base64url_decode(ech).map_err(|e| format!("ech= 解不开：{e}"))
}

/// base64url 解码（SVCB 里用 `-`/`_`、可省 padding）—— 不引依赖，二十来行。
fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => return Err(format!("非法字符 {:?}", c as char)),
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// 真握手：取配置 → `with_ech` → 连上；被拒且服务器给了 retry configs 就**再试一次**。
///
/// 那第二次不是可选的礼节：RFC 9849 §6.1.6 说服务器拒绝时会回它**当前**的配置，
/// 客户端应当用它们重试。本机实测：DNS 取到的 `crypto.cloudflare.com` 配置
/// （`config_id=0x8a`）与服务器当时认的（`0xb0`）不是同一份 —— 旋转竞态，
/// 而服务器正是用 retry configs 把「该用哪份」告诉了我们。
fn ech_handshake(host: &str) -> Result<EchStatus, String> {
    let config_list = fetch_ech_config_list(host)?;
    match ech_attempt(host, config_list.clone()) {
        Err(HandshakeFailed::Retry(Some(configs))) => {
            eprintln!(
                "{host}: 服务器给了 retry configs（{} 条），用它们再试一次",
                configs.len()
            );
            let list = rustls::ech_config_list_bytes(&configs);
            ech_attempt(host, list).map_err(|e| e.to_string())
        }
        other => other.map_err(|e| e.to_string()),
    }
}

enum HandshakeFailed {
    Retry(Option<Vec<rustls::internal::msgs::handshake::EchConfigPayload>>),
    Other(String),
}

/// 把「服务器写回来的字节」抄一份的套接字包装。
///
/// 失败时要能看**服务器到底发了什么**（ServerHello？alert？带 retry configs 的
/// ServerHello？）—— 否则只能看见 rustls 解释完之后的字符串，而「谁先不满意」这件事
/// 恰恰只在原始字节里。这是踩出来的：`Rejected + cannot decrypt` 有两种完全不同的成因
/// （服务器接受了而我们算错，或服务器拒绝了而我们没跟上），原始字节能一句话分开。
struct Recorder<S> {
    inner: S,
    log: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl<S: std::io::Read> std::io::Read for Recorder<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0
            && let Ok(mut l) = self.log.lock()
        {
            l.extend_from_slice(&buf[..n]);
        }
        Ok(n)
    }
}

impl<S: std::io::Write> std::io::Write for Recorder<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl core::fmt::Display for HandshakeFailed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HandshakeFailed::Retry(Some(c)) => {
                write!(f, "服务器拒绝了 ECH 并给了 {} 条 retry configs", c.len())
            }
            HandshakeFailed::Retry(None) => write!(f, "服务器拒绝了 ECH，没给 retry configs"),
            HandshakeFailed::Other(e) => write!(f, "{e}"),
        }
    }
}

fn ech_attempt(host: &str, config_list: Vec<u8>) -> Result<EchStatus, HandshakeFailed> {
    ech_attempt_with_spec(
        host,
        config_list,
        ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).expect("预设"),
    )
}

/// 同 [`ech_attempt`]，但外层指纹由调用方给 —— 用于「逐个变量排查服务器为什么拒」。
fn ech_attempt_with_spec(
    host: &str,
    config_list: Vec<u8>,
    spec: ClientHelloSpec,
) -> Result<EchStatus, HandshakeFailed> {
    // 先用**我们的解析器**验一遍：拿不到配置与配置不合法是两回事，混在一起会误导。
    let list = parse_ech_config_list(&config_list).map_err(|e| {
        HandshakeFailed::Other(format!("{host} 给的 ECHConfigList 我们解不开：{e}"))
    })?;
    let picked = pick_ech_config(&list).ok_or_else(|| {
        HandshakeFailed::Other(format!(
            "{host} 的 {} 条配置里没有一条我们能用的",
            list.len()
        ))
    })?;
    eprintln!(
        "{host}: 配置 {} 条，选中 config_id=0x{:02x} kem=0x{:04x} public_name={}",
        list.len(),
        picked.config_id,
        picked.kem_id,
        String::from_utf8_lossy(&picked.public_name)
    );

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    // 记下发出去的字节：失败时把它们打出来，好让 **uTLS 自己的解码器**（离线探针
    // `ech_decoder_probe_test.go`）判一遍 —— 「服务器到底为什么拒」不该靠猜。
    let outer_sink = Arc::new(std::sync::Mutex::new(Vec::new()));
    let inner_sink = Arc::new(std::sync::Mutex::new(Vec::new()));
    let client = FingerprintClient::new(spec, provider)
        .with_sni(host.to_string())
        .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
        .with_ech(config_list)
        .with_record(outer_sink.clone())
        .with_ech_inner_record(inner_sink.clone());
    let config = utls_engine::client_config(client)
        .map_err(|e| HandshakeFailed::Other(format!("建配置：{e}")))?;

    let addr = format!("{host}:443");
    let tcp = std::net::TcpStream::connect(&addr)
        .map_err(|e| HandshakeFailed::Other(format!("连不上 {addr}：{e}")))?;
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    let conn = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from(host.to_string()).unwrap(),
    )
    .map_err(|e| HandshakeFailed::Other(format!("建连接：{e}")))?;
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut stream = StreamOwned::new(
        conn,
        Recorder {
            inner: tcp,
            log: log.clone(),
        },
    );
    while stream.conn.is_handshaking() {
        if let Err(e) = stream.conn.complete_io(&mut stream.sock) {
            // 拒绝且带 retry configs ⇒ 交给调用方再试一次（RFC 9849 §6.1.6）。
            // `complete_io` 把 TLS 层的错误包成 `io::Error::new(InvalidData, e)` ——
            // 也就是说 **rustls 的错误是那条 io 错误的 source**，用 `downcast_ref` 取回来。
            // （不知道这一点的话，只能看到 `Display` 拼出来的字符串，
            // 而 retry configs 那种**结构化**信息就取不出来了。）
            let retry = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>())
                .and_then(|err| match err {
                    rustls::Error::PeerIncompatible(
                        rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(configs),
                    ) => Some(configs.clone()),
                    _ => None,
                });
            if let Some(configs) = retry {
                return Err(HandshakeFailed::Retry(configs.clone()));
            }
            eprintln!(
                "{host}: 失败时的 ech_status = {:?}（Accepted ⇒ 服务端接受了 ECH，\
                 差异在密钥调度；Grease/Rejected ⇒ 更早的环节）",
                stream.conn.ech_status()
            );
            // 把发出去的字节打出来（十六进制）—— 失败时要能拿它们去问 uTLS 的解码器。
            let hex = |v: &Vec<Vec<u8>>| {
                v.first()
                    .map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<String>())
            };
            if let Ok(o) = outer_sink.lock() {
                eprintln!("{host}: OUTER_HEX={}", hex(&o).unwrap_or_default());
            }
            if let Ok(i) = inner_sink.lock() {
                for (k, form) in i.iter().enumerate() {
                    eprintln!(
                        "{host}: INNER_{}_HEX={}",
                        if k == 0 { "SEALED" } else { "EXPANDED" },
                        form.iter().map(|x| format!("{x:02x}")).collect::<String>()
                    );
                }
            }
            if let Ok(l) = log.lock() {
                eprintln!("{host}: SERVER_BYTES_LEN={}", l.len());
                eprintln!(
                    "{host}: SERVER_BYTES_HEX={}",
                    l.iter().map(|x| format!("{x:02x}")).collect::<String>()
                );
            }
            return Err(HandshakeFailed::Other(format!("握手失败：{e}")));
        }
    }
    Ok(stream.conn.ech_status())
}

#[test]
#[ignore = "要真网络：DNS type-65 + 到一个 ECH 端点的 443。cargo test -- --ignored"]
fn cloudflare_accepts_our_ech_offer() {
    let status = ech_handshake("crypto.cloudflare.com").expect("端到端该跑通");
    assert_eq!(
        status,
        EchStatus::Accepted,
        "服务端没有接受我们的 ECH 提议。注意：`Rejected` 多半意味着 ECHConfig 轮换过、\
         取到的是旧的（本测试每次现取，所以先看上面打印的 public_name）"
    );
}

/// **对照组**：用 **rustls 自带的** ECH 客户端（它**自己**构造内层 hello，不经过本仓的
/// fork 外供路径）打同一个端点。
///
/// 为什么要有这一条：`crypto.cloudflare.com` 判我们 `Rejected`，而判据的每一环在本机
/// 都被证明是对的（uTLS 自己的服务端**接受**我们的提议，见 `ech_utls_server.rs`）。
/// 于是剩下的解释只有一类：「Cloudflare 的接受确认用的是另一份输入」。
/// 这一条把变量缩到**一个** —— 同一个客户端实现（rustls 的确认算法）、同一个端点，
/// 只有**内层 hello 由谁构造**不同：
///
/// - rustls 自带路径：内层 = 外层那个 ClientHello 去过滤 + 压缩（`encode_inner_hello`）；
/// - 本仓路径：内层 = 指纹层按 uTLS 的模型产出的那份（`build_inner_client_hello_body`）。
///
/// 两条都失败 ⇒ Cloudflare 与参照实现不同（记进 `questions/10`）；
/// 只有本仓那条失败 ⇒ 我们的内层构造有问题（而这就给出了定位它的方法）。
#[test]
#[ignore = "要真网络：DNS type-65 + 到一个 ECH 端点的 443。cargo test -- --ignored"]
fn stock_rustls_ech_client_is_the_control() {
    use rustls::client::{EchConfig as RustlsEchConfig, EchMode};
    use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
    use rustls::pki_types::EchConfigListBytes;

    // 两个端点都跑：Cloudflare（我们已被它接受）与 defo.ie（一直 IllegalParameter 的那个）。
    // 对照组在**两个**端点上的结果，才能说明 defo.ie 的拒绝是不是「谁去都拒」。
    for host in ["crypto.cloudflare.com", "defo.ie"] {
        let config_list = fetch_ech_config_list(host).expect("取配置");
        let ech = RustlsEchConfig::new(
            EchConfigListBytes::from(&config_list[..]),
            ALL_SUPPORTED_SUITES,
        )
        .unwrap_or_else(|e| panic!("{host}: 挑配置：{e}"));

        // 与 `ech_attempt` 尽量同参：同 ALPN、同端点。
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_ech(EchMode::Enable(ech))
        .expect("ECH 配置")
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let addr = format!("{host}:443");
        let tcp = std::net::TcpStream::connect(&addr).expect("连不上");
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .ok();
        let conn = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from(host.to_string()).unwrap(),
        )
        .expect("建连接");
        let mut stream = StreamOwned::new(conn, tcp);
        while stream.conn.is_handshaking() {
            if let Err(e) = stream.conn.complete_io(&mut stream.sock) {
                panic!(
                    "{host}: rustls 自带的 ECH 客户端也没谈成（ech_status = {:?}）：{e}\n\
                     ⇒ 这一条把变量缩到一个：内层 hello 由谁构造。它同样失败，\
                     说明该端点与参照实现（uTLS 的服务端）在这件事上不同。",
                    stream.conn.ech_status()
                );
            }
        }
        eprintln!("{host}: rustls 自带客户端 ⇒ {:?}", stream.conn.ech_status());
        assert_eq!(
            stream.conn.ech_status(),
            EchStatus::Accepted,
            "{host}: rustls 自带的 ECH 客户端该被接受"
        );
    }
}

/// 诊断（要网络）：`defo.ie` 的 3 条配置**逐条试**，看服务端到底认哪一条。
///
/// 为什么需要它：`defo.ie` 那三条配置除了 `config_id`（0xb1 / 0xe1 / 0x4a）与公钥之外
/// 完全一样，而 `pick_ech_config` 与 uTLS 一样取**第一条**。若服务端只认其中一条，
/// 「取第一条」就可能取到一个服务器已经轮换掉的 —— 那时错误会是「服务器拒了」，
/// 看起来像我们的实现坏了。逐条试能把那两种情况分开。
#[test]
#[ignore = "要真网络：同上"]
fn try_each_defo_ie_config() {
    let list = fetch_ech_config_list("defo.ie").expect("取配置");
    let configs = parse_ech_config_list(&list).expect("解析");
    for cfg in &configs {
        // 只留这一条：`ECHConfigList = u16 总长 || ECHConfig`。
        let mut single = Vec::new();
        single.extend_from_slice(&(cfg.raw.len() as u16).to_be_bytes());
        single.extend_from_slice(&cfg.raw);
        match ech_attempt("defo.ie", single) {
            Ok(s) => eprintln!("config_id=0x{:02x} ⇒ {s:?}", cfg.config_id),
            Err(e) => eprintln!("config_id=0x{:02x} ⇒ 失败：{e}", cfg.config_id),
        }
    }
}

/// 第二条端点：`defo.ie` 的配置列表里**有多条**（其中含「覆盖用」的假配置），
/// 于是它同时压住「跳过不可用配置、挑出真能用的那条」。
#[test]
#[ignore = "要真网络：同上"]
fn defo_ie_accepts_our_ech_offer() {
    let status = ech_handshake("test.defo.ie").expect("端到端该跑通");
    assert_eq!(
        status,
        EchStatus::Accepted,
        "defo.ie 没有接受我们的 ECH 提议"
    );
}

/// 离线判据：DNS 那一段的解析（base64url + SvcParam 提取）不依赖网络的部分。
#[test]
fn base64url_decoding_matches_the_svcb_flavour() {
    // Cloudflare 那条 `ech=` 的开头（真值取自本机 `dig` 的输出）：
    // 解出来该是一个 `fe0d` 开头的 ECHConfigList。
    let v = base64url_decode("AEX+DQBBigAgACClcPRSYIi9pRSXEYI2Mp1rDDKFgCgesWfIc4Sj2ogUFwAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=")
        .expect("该能解");
    // `ech=` 参数里装的是**整条 ECHConfigList**（含它自己的 u16 长度前缀），
    // 不是单条配置 —— 所以开头是长度而不是版本号（第一版这里写错了，测试当场指出）。
    assert_eq!(
        u16::from_be_bytes([v[0], v[1]]) as usize,
        v.len() - 2,
        "列表长度前缀该与实长自洽"
    );
    let list = parse_ech_config_list(&v).expect("该是一条合法的 ECHConfigList");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].public_name, b"cloudflare-ech.com".to_vec());
    // url 变体（`-`/`_`）与省略 padding 都要能解。
    assert_eq!(base64url_decode("-_-_").unwrap(), vec![0xfb, 0xff, 0xbf]);
    assert_eq!(base64url_decode("AA").unwrap(), vec![0x00]);
    assert!(base64url_decode("A*").is_err(), "非法字符该报错");
}

/// **二分排查**：OpenSSL 系（DEfO）的服务器拒我们的提议，而 Go 系（uTLS 服务端、
/// Cloudflare）与 rustls 自带客户端都被接受。这一条把「外层指纹」当变量逐个试，
/// 找出 OpenSSL 系在意的那一个。
#[test]
#[ignore = "要真网络：同上"]
fn bisect_what_the_openssl_family_rejects() {
    let host = "test.defo.ie";
    let config_list = fetch_ech_config_list(host).expect("取配置");

    let mut specs: Vec<(&str, ClientHelloSpec)> = vec![
        (
            "chrome-70",
            ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap(),
        ),
        (
            "chrome-133",
            ClientHelloSpec::from_preset(ClientHelloId::Chrome(133)).unwrap(),
        ),
        (
            "firefox-120",
            ClientHelloSpec::from_preset(ClientHelloId::Firefox(120)).unwrap(),
        ),
    ];
    // 极简指纹：无 GREASE / 无 padding / 无 ChannelID / 无 compress_certificate，
    // 只有谈成握手必需的那几条 —— 若它能过而 Chrome-70 不能，问题就在「摆样子」的扩展里。
    let mut minimal = ClientHelloSpec::empty();
    minimal.cipher_suites = vec![
        utls::hello::CodePoint::Fixed(0x1301),
        utls::hello::CodePoint::Fixed(0x1302),
        utls::hello::CodePoint::Fixed(0x1303),
    ];
    minimal.extensions = vec![
        utls::hello::Extension::ServerName,
        utls::hello::Extension::SupportedGroups(vec![utls::hello::CodePoint::Fixed(
            utls::values::X25519,
        )]),
        utls::hello::Extension::SignatureAlgorithms(vec![
            utls::hello::CodePoint::Fixed(0x0403),
            utls::hello::CodePoint::Fixed(0x0804),
            utls::hello::CodePoint::Fixed(0x0401),
        ]),
        utls::hello::Extension::KeyShare(utls::hello::KeyShare::groups([
            utls::hello::CodePoint::Fixed(utls::values::X25519),
        ])),
        utls::hello::Extension::PskKeyExchangeModes { modes: vec![1] },
        utls::hello::Extension::SupportedVersions(vec![utls::hello::CodePoint::Fixed(0x0304)]),
    ];
    specs.push(("minimal", minimal));

    for (name, spec) in specs {
        let verdict = match ech_attempt_with_spec(host, config_list.clone(), spec) {
            Ok(s) => format!("{s:?}"),
            Err(e) => format!("失败：{e}"),
        };
        eprintln!("bisect[{host}] {name} ⇒ {verdict}");
    }
}

/// **二分排查（第二步）**：从 Chrome-70 出发逐类剥掉「摆样子」的东西，找出
/// OpenSSL 系服务器在意的那一个。剥的顺序：GREASE 扩展 → GREASE 套件 →
/// GREASE 码点（versions/curves/keyshare 里）→ ChannelID/compress_certificate/padding
/// → TLS 1.2 遗物（EMS/ticket/points/reneg）→ SCT。
#[test]
#[ignore = "要真网络：同上"]
fn bisect_2_which_preset_ornament_offends_openssl() {
    let host = "test.defo.ie";
    let config_list = fetch_ech_config_list(host).expect("取配置");
    let chrome = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap();

    let drop_grease_exts = |mut s: ClientHelloSpec| {
        s.extensions
            .retain(|e| !matches!(e, utls::hello::Extension::Grease));
        s
    };
    let drop_grease_suites = |mut s: ClientHelloSpec| {
        s.cipher_suites
            .retain(|c| !matches!(c, utls::hello::CodePoint::Grease));
        s
    };
    let drop_grease_points = |mut s: ClientHelloSpec| {
        for e in &mut s.extensions {
            match e {
                utls::hello::Extension::SupportedVersions(v)
                | utls::hello::Extension::SupportedGroups(v) => {
                    v.retain(|c| !matches!(c, utls::hello::CodePoint::Grease));
                }
                utls::hello::Extension::KeyShare(v) => {
                    v.groups
                        .retain(|c| !matches!(c, utls::hello::CodePoint::Grease));
                }
                _ => {}
            }
        }
        s
    };
    let drop_ornaments = |mut s: ClientHelloSpec| {
        let drop = [0x7550u16, 27, 21]; // ChannelID / compress_certificate / padding
        s.extensions
            .retain(|e| !e.wire_type().is_some_and(|t| drop.contains(&t)));
        s
    };
    let drop_tls12_relics = |mut s: ClientHelloSpec| {
        let drop = [23u16, 35, 11, 65281, 18]; // EMS / ticket / ec_point_formats / reneg / SCT
        s.extensions
            .retain(|e| !e.wire_type().is_some_and(|t| drop.contains(&t)));
        s
    };

    let mut s = chrome.clone();
    eprintln!("bisect2[0] chrome-70 原样");
    type SpecTransform = (
        &'static str,
        Box<dyn Fn(ClientHelloSpec) -> ClientHelloSpec>,
    );
    let steps: [SpecTransform; 5] = [
        ("−GREASE 扩展", Box::new(drop_grease_exts)),
        ("−GREASE 套件", Box::new(drop_grease_suites)),
        ("−GREASE 码点", Box::new(drop_grease_points)),
        ("−ChannelID/压缩证书/padding", Box::new(drop_ornaments)),
        ("−TLS1.2 遗物 + SCT", Box::new(drop_tls12_relics)),
    ];
    for (i, (name, f)) in steps.into_iter().enumerate() {
        s = f(s);
        let verdict = match ech_attempt_with_spec(host, config_list.clone(), s.clone()) {
            Ok(v) => format!("{v:?}"),
            Err(e) => format!("失败：{e}"),
        };
        eprintln!("bisect2[{}] {name} ⇒ {verdict}", i + 1);
    }
}

/// **二分排查（第三步）**：定位 GREASE 码点里到底是哪一个。分别只从
/// `key_share` / `supported_groups` / `supported_versions` 里去掉 GREASE。
#[test]
#[ignore = "要真网络：同上"]
fn bisect_3_which_grease_codepoint_offends() {
    let host = "test.defo.ie";
    let config_list = fetch_ech_config_list(host).expect("取配置");
    let chrome = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap();

    let scrub = |which: &str, mut s: ClientHelloSpec| {
        for e in &mut s.extensions {
            match (which, e) {
                ("key_share", utls::hello::Extension::KeyShare(ks)) => {
                    ks.groups
                        .retain(|c| !matches!(c, utls::hello::CodePoint::Grease));
                }
                ("groups", utls::hello::Extension::SupportedGroups(v))
                | ("versions", utls::hello::Extension::SupportedVersions(v)) => {
                    v.retain(|c| !matches!(c, utls::hello::CodePoint::Grease));
                }
                _ => {}
            }
        }
        s
    };

    for which in ["key_share", "groups", "versions"] {
        let spec = scrub(which, chrome.clone());
        let verdict = match ech_attempt_with_spec(host, config_list.clone(), spec) {
            Ok(v) => format!("{v:?}"),
            Err(e) => format!("失败：{e}"),
        };
        eprintln!("bisect3[{host}] 只去 {which} 里的 GREASE ⇒ {verdict}");
    }
}
