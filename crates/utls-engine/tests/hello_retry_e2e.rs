//! **端到端 HRR**：让真实的 fork 路径走一趟 HelloRetryRequest。
//!
//! 为什么这条必须端到端：第二飞的字节由 `utls_testdata` 与上游录音逐字节对账，
//! 引擎的接线由 `hello_retry.rs` 单测 —— 但「fork 到底会不会在收到 HRR 时去问
//! `retry_plan`、会不会把第二飞折进 transcript、`kx_state` 有没有跟上」这些只有真的
//! 走一遍状态机才知道。`handle_hello_retry_request` 里那段接线是本仓改动最深的地方。
//!
//! 服务端是**手写的**：只发一条 HRR 然后就不管了（握手不会完成，也不需要完成）——
//! 密码学在这里是多余的，我们要的只是「把第二飞逼出来」。那条 HRR 逐字节抄自
//! uTLS 自带的 `Client-TLSv13-UTLS-HelloRetryRequest-Chrome-70` 夹具的 `Flow 2`
//! （即 openssl 当年回的那条），只把 `legacy_session_id_echo` 换成客户端这次真实发的值。
//!
//! 全程 loopback，无外网。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;
use utls::hello::{ClientHelloId, ClientHelloSpec};
use utls::values as v;
use utls_engine::{FingerprintClient, client_config};

/// 上游夹具路径（同一份录音，指纹层那边用来做逐字节对账）。
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../utls/tests/fixtures/utls-testdata/Client-TLSv13-UTLS-HelloRetryRequest-Chrome-70"
);

/// HRR 的 `random` 字段必须等于 `SHA-256("HelloRetryRequest")`，否则收到的一方会把它
/// 当成普通的 ServerHello 而报「不支持的版本」。这个常量是 RFC 8446 §4.1.4 钉死的。
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// 一条最小但**合法**的 HRR：选了 `TLS_AES_128_GCM_SHA256` 与 P-256。
fn build_hrr(session_id_echo: &[u8]) -> Vec<u8> {
    let mut exts: Vec<u8> = Vec::new();
    // supported_versions = TLS 1.3（HRR 必须带它，否则「不支持 HRR」）
    exts.extend_from_slice(&v::EXT_SUPPORTED_VERSIONS.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&0x0304u16.to_be_bytes());
    // key_share = 选中的组（HRR 里只有组号，没有公钥）
    exts.extend_from_slice(&v::EXT_KEY_SHARE.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&v::CURVE_P256.to_be_bytes());

    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(&HRR_RANDOM);
    body.push(session_id_echo.len() as u8);
    body.extend_from_slice(session_id_echo);
    body.extend_from_slice(&v::TLS_AES_128_GCM_SHA256.to_be_bytes());
    body.push(v::COMPRESSION_NONE);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut msg: Vec<u8> = vec![2u8]; // handshake type = ServerHello（HRR 用同一个类型号）
    let n = body.len();
    msg.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    msg.extend_from_slice(&body);

    let mut rec: Vec<u8> = vec![0x16, 0x03, 0x03];
    rec.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    rec.extend_from_slice(&msg);
    rec
}

/// 读一条完整的握手记录（假定它正好是一条，不带分片）。
fn read_handshake_record(sock: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut head = [0u8; 5];
    sock.read_exact(&mut head)?;
    assert_eq!(head[0], 0x16, "不是握手记录：0x{:02x}", head[0]);
    let len = u16::from_be_bytes([head[3], head[4]]) as usize;
    let mut body = vec![0u8; len];
    sock.read_exact(&mut body)?;
    Ok(body)
}

fn session_id_of(hello: &[u8]) -> Vec<u8> {
    let body = &hello[4..];
    let n = body[34] as usize;
    body[35..35 + n].to_vec()
}

/// 线字节里的扩展类型序列（按线序）。
fn ext_types(hello: &[u8]) -> Vec<u16> {
    let len = ((hello[1] as usize) << 16) | ((hello[2] as usize) << 8) | hello[3] as usize;
    let body = &hello[4..4 + len];
    let mut p = 2 + 32;
    p += 1 + body[p] as usize;
    let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2 + cs;
    p += 1 + body[p] as usize;
    let n = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let region = &body[p..p + n];
    let mut out = Vec::new();
    let mut q = 0usize;
    while q + 4 <= region.len() {
        out.push(u16::from_be_bytes([region[q], region[q + 1]]));
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        q += 4 + bl;
    }
    out
}

/// 夹具里第 `flow` 条记录里的握手消息（Go 的转储每行**两组 8 字节**）。
fn fixture_flow(flow: u32) -> Vec<u8> {
    let text = std::fs::read_to_string(FIXTURE).expect("读夹具");
    let mut record: Vec<u8> = Vec::new();
    let mut want = false;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(">>> Flow ") {
            let n: u32 = rest.split_whitespace().next().unwrap().parse().unwrap();
            if n == flow {
                want = true;
            } else if want {
                break;
            }
            continue;
        }
        if !want {
            continue;
        }
        for tok in line.split('|').next().unwrap().split_whitespace() {
            if tok.len() == 2 && tok.bytes().all(|b| b.is_ascii_hexdigit()) {
                record.push(u8::from_str_radix(tok, 16).unwrap());
            }
        }
    }
    for i in 0..record.len().saturating_sub(4) {
        if record[i] == 0x16 {
            let len = u16::from_be_bytes([record[i + 3], record[i + 4]]) as usize;
            if i + 5 + len == record.len() {
                return record[i + 5..].to_vec();
            }
        }
    }
    panic!("夹具的 Flow {flow} 里没有自洽的握手记录");
}

#[test]
fn a_real_hello_retry_request_goes_through_the_fork_and_the_second_flight_matches_the_recording() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("绑定回环端口");
    let addr = listener.local_addr().unwrap();

    let server = thread::spawn(move || -> std::io::Result<(Vec<u8>, Vec<u8>)> {
        let (mut sock, _) = listener.accept()?;
        let first = read_handshake_record(&mut sock)?;
        // 回显客户端这次真实发的 session id（RFC 要求，rustls 会校验）。
        sock.write_all(&build_hrr(&session_id_of(&first)))?;
        sock.flush()?;
        let second = read_handshake_record(&mut sock)?;
        Ok((first, second))
    });

    // 客户端：完全走生产路径（`client_config` + 外供 ClientHello 的 fork）。
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap();
    let client = FingerprintClient::new(
        spec,
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    )
    .with_client_random([0u8; 32])
    .with_sni("");
    let config = Arc::new(client_config(client).expect("建配置"));
    let mut conn = ClientConnection::new(config, ServerName::try_from("example.com").unwrap())
        .expect("建连接");
    let mut sock = TcpStream::connect(addr).expect("连回环");

    // 握手不会完成（服务端发完 HRR 就不管了），但那**不**是本条要证的事：
    // 两飞都已经发出去了。忽略这里的错误，去看服务端收到了什么。
    if let Err(e) = conn.complete_io(&mut sock) {
        eprintln!("（预期之内：服务端发完 HRR 就不管了）客户端报错：{e}");
    }

    let (first, second) = server.join().expect("服务端线程").expect("服务端 IO");
    let expected_first = fixture_flow(1);
    let expected_second = fixture_flow(3);

    // ① 第一飞：**结构**等于上游录音。不逐字节比 —— 夹具的 session id 与 GREASE 取值
    //    来自 uTLS 那次运行的 `zeroSource{}` 与它自己的熵（分别是 32 个零与 0x0a0a），
    //    而我们是种子里抽的。逐字节比在**指纹层**那边做（`utls_testdata` 把这两样都钉住），
    //    这里要证的是「真实的 fork 路径确实把第一飞原样发了出去」。
    assert_eq!(first.len(), expected_first.len(), "第一飞长度与录音不符");
    let norm = |ts: Vec<u16>| -> Vec<u16> {
        ts.into_iter()
            .map(|t| if v::is_grease(t) { 0x0a0a } else { t })
            .collect()
    };
    assert_eq!(
        norm(ext_types(&first)),
        norm(ext_types(&expected_first)),
        "第一飞的扩展类型序列与录音不符"
    );
    assert_eq!(
        &first[..6],
        &expected_first[..6],
        "第一飞的握手头/legacy_version 不符"
    );

    // ② 第二飞：**真的发出去了**，且结构等于夹具的 Flow 3。
    assert_eq!(
        second.len(),
        expected_second.len(),
        "第二飞长度与录音不符（填充算术或 key_share 长度错了）"
    );
    assert_eq!(
        session_id_of(&first),
        session_id_of(&second),
        "第二飞换了 session id"
    );
    assert_eq!(
        &first[6..38],
        &second[6..38],
        "第二飞换了客户端随机数（RFC 8446 §4.1.2 禁止）"
    );
    assert_eq!(
        norm(ext_types(&second)),
        norm(ext_types(&expected_second)),
        "第二飞的扩展类型序列与录音不符"
    );

    // ③ key_share 只剩服务器要的那个组。公钥字节是新的（每连接一把私钥），
    //    所以这里比的是「组 + 公钥长度」，与夹具一致。
    let ks = |h: &[u8]| -> Vec<u8> {
        let len = ((h[1] as usize) << 16) | ((h[2] as usize) << 8) | h[3] as usize;
        let body = &h[4..4 + len];
        let mut p = 2 + 32;
        p += 1 + body[p] as usize;
        let cs = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2 + cs;
        p += 1 + body[p] as usize;
        let n = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
        p += 2;
        let region = &body[p..p + n];
        let mut q = 0usize;
        while q + 4 <= region.len() {
            let ty = u16::from_be_bytes([region[q], region[q + 1]]);
            let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
            if ty == v::EXT_KEY_SHARE {
                return region[q + 4..q + 4 + bl].to_vec();
            }
            q += 4 + bl;
        }
        panic!("没有 key_share");
    };
    assert_eq!(
        &ks(&second)[..4],
        &[0x00, 0x45, 0x00, 0x17],
        "第二飞该只报 P-256 一项"
    );
    assert_eq!(
        ks(&second).len(),
        ks(&expected_second).len(),
        "key_share 体长该与录音相同"
    );
    assert_ne!(
        ks(&first),
        ks(&second),
        "key_share 没变说明第二飞没换密钥交换"
    );

    // ④ 第二飞**不是**第一飞的复制（那是最容易犯的错：fork 里早返回用错了 plan）。
    assert_ne!(second, first);
}
