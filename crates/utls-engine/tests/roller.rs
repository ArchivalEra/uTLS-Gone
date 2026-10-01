//! **`Roller` 的判据**：顺序重试、记住能通的那条、两类失败的处置不同。
//!
//! uTLS 没有 `Roller` 的测试（只有 `examples/old/examples.go` 里一个用法示例），
//! 所以判据是本仓自己搭的 —— 而搭法刻意只用**可数的事实**：
//!
//! - 「失败的候选**一个字节都没发出去**」：用 `ClientHelloId::Golang` 当失败候选，
//!   它在 `from_preset` 就报 `EngineDefined`（本架构里没有它的 spec），
//!   于是那条候选只会**占掉一次 TCP 连接**、不产 ClientHello —— 服务端那边可数；
//! - 「成功的那条真的谈成了、而且是 Chrome-70 的形状」：服务端记录到的 ClientHello
//!   里有 Chrome-70 的独有扩展（`0x7550` ChannelID）；
//! - 「记住了」：[`Roller::working_hello_id`] 是直读的，而 `candidate_order` 把
//!   记住的那条排最前也是直读的（不必从线上字节反推顺序）。

mod common;

use std::sync::Arc;

use rustls::ClientConnection;
use rustls::pki_types::ServerName;
use utls::hello::ClientHelloId;
use utls_engine::roller::Roller;
use utls_engine::{FingerprintClient, UConn};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// 一个「用自签证书的本地服务端」版建连闭包：`Roller` 的传输是可注入的，这里就注入它。
fn local_tls(
    sock: std::net::TcpStream,
    client: FingerprintClient,
    server_name: &str,
) -> Result<UConn, Box<dyn std::error::Error>> {
    let config = Arc::new(common::client_config_with_verifier(
        client,
        Vec::new(),
        common::shared_verifier(),
        None,
    ));
    let mut conn = ClientConnection::new(config, ServerName::try_from(server_name.to_string())?)?;
    let mut sock = sock;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)?;
    }
    Ok(UConn::from_connection(conn, sock))
}

/// 记录到的 ClientHello 里有没有某个扩展类型。
fn has_ext(record: &[u8], want: u16) -> bool {
    let msg = &record[5..];
    let len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    let body = &msg[4..4 + len];
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
        if u16::from_be_bytes([region[q], region[q + 1]]) == want {
            return true;
        }
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        q += 4 + bl;
    }
    false
}

#[test]
fn it_tries_candidates_in_order_remembers_the_winner_and_reuses_it_first() {
    // 候选：先一条**注定失败**的（Golang 本架构无 spec），再一条能通的（Chrome-70）。
    let mut roller = Roller::new(provider())
        .with_hello_ids(vec![ClientHelloId::Golang, ClientHelloId::Chrome(70)])
        // 固定种子 ⇒ 打乱也可复现（这里两条候选，打乱后 Chrome-70 可能在前 —— 所以
        // 这条测试不依赖顺序，只依赖「最后能通的是 Chrome-70」）。
        .with_seed([7u8; 32]);

    // 第一条连接：会先试 Golang（失败、不产字节），再试 Chrome-70（谈成）。
    let (addr, handle) = common::spawn_server(common::server_config(false, None), 1);
    let (_conn, winner) = roller
        .dial(addr, "localhost", &mut |sock, client, name| {
            local_tls(sock, client, name)
        })
        .expect("至少有一条候选能通");
    assert_eq!(winner, ClientHelloId::Chrome(70), "能通的该是 Chrome-70");
    assert_eq!(
        roller.working_hello_id(),
        Some(ClientHelloId::Chrome(70)),
        "该记住它"
    );
    // 顺序：记住的那条在最前（uTLS 的 `push working hello ID first`）。
    assert_eq!(
        roller.candidate_order().first().copied(),
        Some(ClientHelloId::Chrome(70)),
        "记住的预设该排在最前，下一轮先试它"
    );

    let served = handle.join().expect("服务端线程");
    assert_eq!(
        served.len(),
        1,
        "只该建立一条 TCP 连接（Golang 那条在 build 阶段就失败了）"
    );
    let hellos = &served[0].client_hellos;
    assert_eq!(hellos.len(), 1, "只该发出**一条** ClientHello");
    assert!(
        has_ext(&hellos[0], 0x7550),
        "那条 hello 该是 Chrome-70 的形状（ChannelID 0x7550）"
    );

    // ── 第二条连接：必须先试记住的那条，一次谈成 ──
    let (addr, handle) = common::spawn_server(common::server_config(false, None), 1);
    let (_conn, winner2) = roller
        .dial(addr, "localhost", &mut |sock, client, name| {
            local_tls(sock, client, name)
        })
        .expect("第二轮该一次谈成");
    assert_eq!(winner2, ClientHelloId::Chrome(70));
    let served = handle.join().expect("服务端线程");
    assert_eq!(
        served[0].client_hellos.len(),
        1,
        "第二轮该**一次**谈成：记住的预设排在第一位，不该再多试一条"
    );
}

/// 全部候选都谈不成 ⇒ 返回错误，且**不**记住任何预设。
#[test]
fn all_candidates_failing_leaves_no_working_id() {
    let mut roller = Roller::new(provider())
        .with_hello_ids(vec![ClientHelloId::Golang, ClientHelloId::Golang])
        .with_seed([1u8; 32]);
    let (addr, handle) = common::spawn_server(common::server_config(false, None), 1);
    // 注意：Golang 在 `from_preset` 就失败 ⇒ 连 TCP 都不建 ⇒ 服务端不会收到连接。
    // 所以这里**不能** `join()`（它会一直等在 `accept()` 上）；拿到地址就够了。
    let err = roller
        .dial(addr, "localhost", &mut |sock, client, name| {
            local_tls(sock, client, name)
        })
        .expect_err("全是坏候选时该报错");
    let text = err.to_string();
    assert!(
        text.contains("golang") || text.contains("没有 spec"),
        "错误该来自最后那条候选的 build 失败（`golang` 在本架构里没有 spec）：{text}"
    );
    assert_eq!(
        roller.working_hello_id(),
        None,
        "一条都没通，不该记住任何预设"
    );
    drop(handle);
}

/// **TCP 失败与 TLS 失败处置不同**：连不上就直接返回（不再试别的候选）。
///
/// 这条是 uTLS `Dial` 里那个 `return nil, err` 与 `continue` 的区别，也是最容易抄错的一处：
/// 抄成 `continue` 会让「端口没人听」变成「把所有预设都试一遍」。
#[test]
fn a_tcp_failure_returns_immediately_instead_of_trying_more_candidates() {
    let mut roller = Roller::new(provider())
        .with_hello_ids(vec![ClientHelloId::Chrome(70), ClientHelloId::Firefox(148)])
        .with_seed([3u8; 32]);
    // 一个**没人听**的端口：绑定后立刻放掉，端口随即空闲（loopback 上基本立即可复现）。
    let addr = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定");
        let a = l.local_addr().expect("地址");
        drop(l);
        a
    };
    let calls = std::cell::Cell::new(0usize);
    let err = roller
        .dial(addr, "localhost", &mut |sock, client, name| {
            calls.set(calls.get() + 1);
            local_tls(sock, client, name)
        })
        .expect_err("连不上该报错");
    assert_eq!(
        calls.get(),
        0,
        "TCP 都没连上，就不该走到谈 TLS 那一步（更不该把候选轮一遍）"
    );
    assert!(
        err.to_string().to_lowercase().contains("refused")
            || err.to_string().to_lowercase().contains("connection"),
        "错误该是连接层的：{err}"
    );
}
