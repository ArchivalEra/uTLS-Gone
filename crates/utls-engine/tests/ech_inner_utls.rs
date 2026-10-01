//! **内层 hello 与 uTLS 自己产出的那份逐字节比**（ECH 内层的保真判据）。
//!
//! # 为什么要有这一条
//!
//! ECH 的接受那一半曾是全仓唯一红着的判据（`questions/10-ech-acceptance-falsified.md`，
//! 已 resolved）：`crypto.cloudflare.com` 判 `Rejected` 而我们这边密钥分叉，`defo.ie`
//! 直接 `IllegalParameter`。排查时建立的第一条判据就是「内层的形状对不对」不该由我复述
//! —— 该由 **uTLS 自己的字节**判。这条测试留了下来，守着「我们的内层 == uTLS 的内层」
//! 这条保真性质（那条线的真正修复：内层按 uTLS 的诚实模型造 + fork 把**外层**的
//! session id 喂给转录 + ECH 路径去掉 GREASE keyshare）。
//!
//! 内层不是公开 API（`GetInnerClientHello` 在这一版已删），所以字节由入库探针取：
//! `crates/utls/tests/fixtures/gen-reference/ech_inner_probe_test.go`，复制进 uTLS 源码目录跑
//!
//! ```text
//! cd /tmp/utls-ref/utls-master
//! HEX=$(dig +short -t TYPE65 crypto.cloudflare.com @1.1.1.1 | tr ' ' '\n' \
//!        | sed -n 's/^ech=//p' | tr '_-' '/+' | base64 -d | od -An -tx1 | tr -d ' \n')
//! go test -run TestProbeECHInner -v -ech-config-hex "$HEX"
//! ```
//!
//! # 为什么是「逐字节」而不是「结构差不多」
//!
//! 服务端**重建**内层（把 `0xfd00` 展开）之后按那串字节算转录，接受确认
//! （`HKDF(握手密钥, Hash(内层转录 || ServerHello*))`）要两位一致才算接受。
//! 所以长度对、扩展集合对都还不够 —— **顺序与位置**也在转录里。
//!
//! # 下面这串字节的可比性（怎么让两边真的可比）
//!
//! 两边都被钉成同一组输入：
//!
//! | 输入 | 取值 | 为什么 |
//! |---|---|---|
//! | 预设 | Chrome-70 | 探针用 `HelloChrome_70`（它在 uTLS 里**不**做乱序，106+ 才乱序） |
//! | 随机数 | 全零 | 探针那边是 `getUTLSTestConfig()` 的固定随机数 |
//! | SNI | `crypto.cloudflare.com` | 探针 `SetSNI` 就是这个；**内层放真名、外层放公开名** |
//! | `maximum_name_length` | `0` | 取的是 `crypto.cloudflare.com` 当时那条 DNS 配置里的值 |
//! | key_share 公钥 | 32 字节定值 | 内层里它被压缩进 `0xfd00`，**字节本身不进内层** |
//!
//! 于是剩下的差异只可能来自**内层那几条规则本身**，也就是这条线要找的东西。
//!
//! # ⚠️ 这串期望值的有效期
//!
//! 它**不**依赖服务器的 HPKE 公钥（公钥不进内层），只依赖「uTLS 的 Chrome-70 预设」
//! 与「配置里的 `maximum_name_length`」。配置轮换不影响它；而预设变了这条会红 ——
//! 那正是它该红的时候（那时要么更新期望值，要么承认指纹变了）。

mod common;

use std::sync::{Arc, Mutex};

use rustls::ClientConnection;
use rustls::pki_types::ServerName;
use utls::hello::{ClientHelloId, ClientHelloSpec, HandshakeInputs};
use utls::values as v;
use utls_engine::FingerprintClient;

/// uTLS 的探针在 Chrome-70 / 零随机数 / SNI `crypto.cloudflare.com` /
/// `maximum_name_length=0` 下产出的**内层明文**（含末尾补零，共 128 字节），
/// 原样取自 `TestProbeECHInner` 的 `PROBE encodedInner_hex=` 一行。
const UTLS_INNER_HEX: &str = "030300000000000000000000000000000000000000000000000000000000000000000000061303130113020100003b0000001a001800001563727970746f2e636c6f7564666c6172652e636f6d00120000fe0d000101002b0003020304fd00000908000d00050033000a00000000000000000000000000000000000000000000";

/// **离线判据（Go 侧，服务端那一半）**：用**我们自己生成的** ECH 密钥对封一条真提议，
/// 把「服务器需要的全部输入」打出来（外层 hello、密封的内层明文、ECHConfig、私钥），
/// 交给 **uTLS 自己的 ECH 服务端** 跑一遍。
///
/// 为什么这是最关键的一格：`processECHClientHello` 只在**一处**发 `IllegalParameter`
/// —— `decodeInnerClientHello` 失败（解不开密文时它**不发 alert**，而是当没提议过、
/// 退回外层）。所以「服务器到底为什么拒」这个问题，只有让**服务器的代码自己说**
/// 才算答完（`crates/utls/tests/fixtures/gen-reference/ech_server_probe_test.go`）。
///
/// 用法：
///
/// ```text
/// cargo test -p utls-engine --test ech_inner_utls -- --nocapture dump_for_the_utls_server
/// # 把三串 hex 与配置交给：
/// cd /tmp/utls-ref/utls-master
/// go test -run TestProbeECHServer -v -srv-outer-hex <..> -srv-config-hex <..> -srv-priv-hex <..>
/// ```
#[test]
fn dump_for_the_utls_server() {
    let suite = common::ech_hpke_suite();
    let (public_key, private_key) = suite.generate_key_pair().expect("生成 ECH 密钥");
    // `public_name = public.example`、`maximum_name_length = 0`（与探针那份同形）。
    let config_list = common::ech_config_list(&public_key.0, 0x44, &[]);

    let outer_sink = Arc::new(Mutex::new(Vec::new()));
    let inner_sink = Arc::new(Mutex::new(Vec::new()));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client = FingerprintClient::new(
        ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).expect("预设"),
        provider,
    )
    // 内层放**真名**（服务器按它认证），外层放 `public.example`（配置里的公开名）。
    .with_sni("secret.example")
    .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    .with_ech(config_list.clone())
    .with_record(outer_sink.clone())
    .with_ech_inner_record(inner_sink.clone());

    let (addr, server) = common::spawn_server(common::server_config(false, None), 1);
    let config = Arc::new(common::client_config_with_verifier(
        client,
        Vec::new(),
        common::shared_verifier(),
        None,
    ));
    let mut conn = ClientConnection::new(config, ServerName::try_from("secret.example").unwrap())
        .expect("建连接");
    let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
    let _ = common::drive_client(&mut conn, &mut sock);
    let _ = server.join();

    let outer = outer_sink.lock().unwrap()[0].clone();
    let inner = inner_sink.lock().unwrap()[0].clone();
    assert_eq!(outer[0], 1, "记录的该是 ClientHello 握手消息");
    eprintln!("OUTER_HEX={}", hex_of(&outer));
    eprintln!("INNER_SEALED_HEX={}", hex_of(&inner));
    // `ECHConfigList = u16 总长 || ECHConfig` ⇒ 单条配置从下标 2 开始。
    eprintln!("CONFIG_HEX={}", hex_of(&config_list[2..]));
    eprintln!("PRIV_HEX={}", hex_of(private_key.secret_bytes()));
    eprintln!(
        "PUBKEY_LEN={} INNER_LEN={}",
        public_key.0.len(),
        inner.len()
    );
}

fn hex_of(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// **离线判据（Go 侧）**：把我们发出去的外层 hello 与封进去的内层明文打出来，
/// 交给 **uTLS 自己的服务端解码器** `decodeInnerClientHello` 判。
///
/// 为什么这不是「再写一遍我的猜测」：`defo.ie`（Go 系服务端）拒我们的方式是
/// `IllegalParameter`，而那个 alert 在 uTLS/Go 的服务端代码里**只有一个出处** ——
/// `decodeInnerClientHello` 返回了错误。于是「uTLS 的解码器吃不吃我们的内层」
/// 就是那条失败**离线可复跑**的等价物。
///
/// 用法：
///
/// ```text
/// cargo test -p utls-engine --test ech_inner_utls -- --nocapture dump
/// # 把打出来的 OUTER_HEX / INNER_HEX 交给：
/// cd /tmp/utls-ref/utls-master
/// go test -run TestProbeECHDecode -v -outer-hex <OUTER> -inner-hex <INNER>
/// ```
#[test]
fn dump_outer_and_inner_for_the_utls_decoder() {
    let suite = common::ech_hpke_suite();
    let (public_key, _private) = suite.generate_key_pair().expect("生成 ECH 密钥");
    let config_list = common::ech_config_list(&public_key.0, 0x44, &[]);

    let outer_sink = Arc::new(Mutex::new(Vec::new()));
    let inner_sink = Arc::new(Mutex::new(Vec::new()));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client = FingerprintClient::new(
        ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).expect("预设"),
        provider,
    )
    .with_sni("localhost")
    .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    .with_ech(config_list)
    .with_record(outer_sink.clone())
    .with_ech_inner_record(inner_sink.clone());

    let (addr, server) = common::spawn_server(common::server_config(false, None), 1);
    let config = Arc::new(common::client_config_with_verifier(
        client,
        Vec::new(),
        common::shared_verifier(),
        None,
    ));
    let mut conn =
        ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).expect("建连接");
    let mut sock = std::net::TcpStream::connect(addr).expect("连回环");
    // 本机服务端不接受 ECH ⇒ 必然报错；我们要的是**发出去的那串字节**。
    let _ = common::drive_client(&mut conn, &mut sock);
    let _ = server.join();

    let outer = outer_sink.lock().unwrap()[0].clone();
    let inner_records = inner_sink.lock().unwrap().clone();
    assert_eq!(
        inner_records.len(),
        2,
        "每次提议该记两条：密封形态 + 转录形态"
    );
    let inner = inner_records[0].clone();
    let expanded = inner_records[1].clone();
    // 记录槽里放的**就是握手消息本身**（`plan()` 记的是它，不含 5 字节记录头）——
    // 而解码器要的正是它。第一版这里多剥了 5 字节，Go 侧当场报「外层解不开」。
    assert_eq!(outer[0], 1, "记录的该是 ClientHello 的握手消息（type=1）");
    eprintln!("OUTER_HEX={}", hex_of(&outer));
    eprintln!("INNER_HEX={}", hex_of(&inner));
    eprintln!("INNER_LEN={}", inner.len());
    // 转录形态：服务器重建出来的那串字节该与它逐字节相同。
    eprintln!("EXPANDED_LEN={}", expanded.len());
    eprintln!("EXPANDED_HEX={}", hex_of(&expanded));
    assert_eq!(inner.len() % 32, 0, "内层明文该补零到 32 的倍数");
}

/// 我们封进去的那份（`sealed` + 补零）= 服务器解出来的明文，逐字节等于 uTLS 的产物。
#[test]
fn our_inner_hello_is_byte_identical_to_utls_chrome70() {
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).expect("Chrome-70 预设");
    let mut inputs = HandshakeInputs::deterministic([0u8; 32]);
    // 探针那边的随机数是全零（`getUTLSTestConfig()` 的固定值），这里对齐它。
    inputs.client_random = [0u8; 32];
    inputs.sni = Some("crypto.cloudflare.com".into());
    inputs.key_exchange = vec![(v::X25519, vec![0x5Au8; 32])];

    // uTLS 的 Chrome-70 预设不乱序（106+ 才乱序），所以外层线序 = spec 顺序。
    // GREASE 的类型每连接才定（`wire_type() == None`），但它们不进 marker，
    // 所以这里给不给出都一样。
    let outer_ext_order: Vec<u16> = spec
        .extensions
        .iter()
        .filter_map(|e| e.wire_type())
        .collect();

    // cipher suites 是内层的**输入**（uTLS 取 `config.cipherSuites()`），不是本函数的产物；
    // 这里钉成探针那台机器上 uTLS 实际产出的清单（`defaultCipherSuitesTLS13NoAES` 的顺序），
    // 好让「同样的输入 ⇒ 逐字节相同的输出」这个判据成立。
    let cipher_suites: Vec<u16> = vec![0x1303, 0x1301, 0x1302];

    let inner = utls_engine::ech::build_inner_client_hello_body(
        &spec,
        &inputs,
        &utls_engine::ech::InnerHelloInputs {
            sni: inputs.sni.as_deref(),
            alpn: &[], // 探针的配置没设 NextProtos ⇒ uTLS 的内层没有 ALPN
            cipher_suites: &cipher_suites,
            outer_ext_order: &outer_ext_order,
            maximum_name_length: 0,
            resuming: false,
        },
    )
    .expect("内层该能构造");

    let mut ours = inner.sealed.clone();
    ours.extend(std::iter::repeat_n(0, inner.pad));
    let want = UTLS_INNER_HEX;

    assert_eq!(
        hex_of(&ours),
        want,
        "内层明文与 uTLS 自己的产物不一致（探针命令见本文件模块头）。\n\
         我们的（{} 字节）：{}\n\
         uTLS 的（{} 字节）：{}",
        ours.len(),
        hex_of(&ours),
        want.len() / 2,
        want
    );
    assert_eq!(ours.len() % 32, 0, "内层明文该补零到 32 的倍数");
}
