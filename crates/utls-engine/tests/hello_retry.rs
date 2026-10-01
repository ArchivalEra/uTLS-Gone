//! **HRR 第二飞**在引擎侧的接线测试（离线，不需要服务器）。
//!
//! 分工要说清：**第二飞的字节**由 `crates/utls/tests/utls_testdata.rs` 与 uTLS 自带的
//! `Flow 3` 录音逐字节对账（那是权威判据）。这里测的是**引擎的接线**：
//!
//! 1. `retry_plan` 必须**复用**第一飞的输入 —— 客户端随机数、GREASE、乱序、session id
//!    逐字节不变（RFC 8446 §4.1.2 只允许改 key_share / cookie / PSK / padding）。
//!    这条在引擎层特别容易被写错：`plan()` 里是 `HandshakeInputs::os()`，
//!    第二飞若再调一次 `os()`，随机数就变了 —— 而那种错在**握手仍然成功**的掩盖下不可见。
//! 2. `key_share` 只剩服务器选中的那个组，且**带一把新的私钥**（公钥字节会变）。
//! 3. cookie-only 的 HRR（`selected_group: None`）：`key_share` 不变、`key_exchange` 为
//!    `None`（引擎继续用第一飞那把交换），并多出一条 `cookie` 扩展。
//! 4. 缺 `key_share` 扩展的 spec、或服务器要一个没声明过的组 → 明确报错，不猜。

use std::sync::Arc;

use rustls::client::{PlanRequest, ResumptionOffer, SuppliesClientHello};
use rustls::crypto::CryptoProvider;
use utls::hello::{ClientHelloId, ClientHelloSpec};
use utls::values as v;
use utls_engine::FingerprintClient;

/// 引擎侧那套 provider（与 `UClient::new` 用的一致：aws-lc-rs）。
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// 引擎能完成的组（与 `fork_key_exchange_groups` 同一口径）。
/// 一次没有会话可复用的 plan 请求。
fn plan_req(groups: &[u16]) -> PlanRequest {
    PlanRequest {
        groups: groups.to_vec(),
        resumption: None,
    }
}

/// 一个假的复用提议（数据形态而已 —— binder 由引擎自己算）。
fn offer() -> ResumptionOffer {
    ResumptionOffer {
        ticket: vec![0xAB; 16],
        obfuscated_ticket_age: 42,
        binder_len: 32,
    }
}

fn engine_groups() -> Vec<u16> {
    provider()
        .kx_groups
        .iter()
        .filter(|g| g.usable_for_version(rustls::ProtocolVersion::TLSv1_3))
        .map(|g| u16::from(g.name()))
        .collect()
}

fn chrome_70() -> FingerprintClient {
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Chrome(70)).unwrap();
    // 钉死随机数：RFC 判据要求它跨两飞逐字节相同，而 `os()` 每次都给新的。
    FingerprintClient::new(spec, provider())
        .with_client_random([0u8; 32])
        .with_sni("")
}

/// 线字节里的扩展 `(类型, 体)`，按线序。
fn exts(hello: &[u8]) -> Vec<(u16, Vec<u8>)> {
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
        let ty = u16::from_be_bytes([region[q], region[q + 1]]);
        let bl = u16::from_be_bytes([region[q + 2], region[q + 3]]) as usize;
        out.push((ty, region[q + 4..q + 4 + bl].to_vec()));
        q += 4 + bl;
    }
    out
}

fn random_of(hello: &[u8]) -> Vec<u8> {
    hello[6..38].to_vec()
}

fn session_id_of(hello: &[u8]) -> Vec<u8> {
    let body = &hello[4..];
    let n = body[34] as usize;
    body[35..35 + n].to_vec()
}

fn body_of(hello: &[u8], ty: u16) -> Option<Vec<u8>> {
    exts(hello)
        .into_iter()
        .find(|(t, _)| *t == ty)
        .map(|(_, b)| b)
}

#[test]
fn retry_reuses_the_first_flight_inputs_and_only_rewrites_key_share() {
    use rustls::client::HelloRetryRequestPlan;

    let client = chrome_70();
    let groups = engine_groups();
    let first = client.plan(&plan_req(&groups)).unwrap();
    let first_bytes = first.client_hello.clone().unwrap();

    let retry = client
        .retry_plan(&HelloRetryRequestPlan {
            selected_group: Some(v::CURVE_P256),
            cookie: None,
            engine_groups: groups.clone(),
            resumption: None,
        })
        .expect("第二飞该能产出");
    let second_bytes = retry.client_hello.clone().unwrap();
    let second_kx = retry
        .key_exchanges
        .first()
        .cloned()
        .expect("换了组就该带新交换");
    assert_eq!(
        second_kx.group(),
        v::CURVE_P256,
        "新交换该是服务器要的那个组"
    );

    // ① RFC 8446 §4.1.2：只有 key_share 与 padding 可以变。
    assert_eq!(
        random_of(&first_bytes),
        random_of(&second_bytes),
        "第二飞换了客户端随机数 —— RFC 禁止，而且这是最容易漏的一条"
    );
    assert_eq!(
        session_id_of(&first_bytes),
        session_id_of(&second_bytes),
        "第二飞换了 session id"
    );
    assert_eq!(
        first_bytes.len(),
        second_bytes.len(),
        "第二飞的总长变了（填充该让出 key_share 长出来的部分）"
    );
    let a = exts(&first_bytes);
    let b = exts(&second_bytes);
    assert_eq!(
        a.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
        b.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
        "第二飞改了扩展的类型序列或顺序"
    );
    let mut changed: Vec<u16> = Vec::new();
    for ((ta, ba), (_, bb)) in a.iter().zip(b.iter()) {
        if ba != bb {
            changed.push(*ta);
        }
    }
    assert_eq!(
        changed,
        vec![v::EXT_KEY_SHARE, v::EXT_PADDING],
        "除 key_share 与 padding 之外还有扩展变了"
    );

    // ② key_share 只剩选中的组，而且是**新的**公钥（新的一把私钥）。
    let ks = body_of(&second_bytes, v::EXT_KEY_SHARE).unwrap();
    assert_eq!(
        &ks[..4],
        &[0x00, 0x45, 0x00, 0x17],
        "该只剩 P-256 一项（0x0017）"
    );
    let first_ks = body_of(&first_bytes, v::EXT_KEY_SHARE).unwrap();
    assert_ne!(first_ks, ks, "key_share 没变说明没起新密钥交换");
    assert_ne!(ks[6..], first_ks[6..], "公钥字节该是新的（每连接一把私钥）");
}

#[test]
fn cookie_only_retry_keeps_the_offered_key_share() {
    use rustls::client::HelloRetryRequestPlan;

    let client = chrome_70();
    let groups = engine_groups();
    let first = client.plan(&plan_req(&groups)).unwrap();
    let first_bytes = first.client_hello.clone().unwrap();

    let retry = client
        .retry_plan(&HelloRetryRequestPlan {
            selected_group: None, // cookie-only
            cookie: Some(b"a-cookie".to_vec()),
            engine_groups: groups.clone(),
            resumption: None,
        })
        .expect("cookie-only 的第二飞该能产出");
    let second_bytes = retry.client_hello.clone().unwrap();

    // key_share 原样保留 ⇒ 不需要新交换，引擎继续用第一飞那把。
    assert!(
        retry.key_exchanges.is_empty(),
        "cookie-only 的 HRR 不该换密钥交换 —— 换了就等于换了 key_share"
    );
    assert_eq!(
        body_of(&first_bytes, v::EXT_KEY_SHARE),
        body_of(&second_bytes, v::EXT_KEY_SHARE),
        "cookie-only 的第二飞该保留原来的 key_share"
    );
    assert_eq!(
        body_of(&second_bytes, v::EXT_COOKIE).expect("该多出一条 cookie 扩展"),
        [0, 8, b'a', b'-', b'c', b'o', b'o', b'k', b'i', b'e'],
        "cookie 的体 = u16 长度 + 原字节"
    );
    // 多了一条 14 字节的扩展，**但总长不变** —— `BoringPaddingStyle` 会把填充让出来：
    // uTLS 自带夹具里的第二飞就是这么表现的（key_share 长 28、padding 就短 28，总长恒定）。
    assert_eq!(
        second_bytes.len(),
        first_bytes.len(),
        "总长该不变：填充会让出 cookie 占的 14 字节"
    );
    let pad = |h: &[u8]| body_of(h, v::EXT_PADDING).map(|b| b.len()).unwrap_or(0);
    assert_eq!(
        pad(&second_bytes) + 14,
        pad(&first_bytes),
        "填充该正好让出 14 字节（cookie 扩展头 4 + u16 长度前缀 2 + 8 字节 cookie）"
    );
}

#[test]
fn retry_refuses_what_it_cannot_express() {
    use rustls::client::HelloRetryRequestPlan;

    // ① 还没发过第一飞就要第二飞 ⇒ 没有可复用的输入，必须报错而不是现造一份
    //    （现造就等于换了客户端随机数，RFC 8446 §4.1.2 禁止）。
    //    「spec 里没有 key_share 扩展」那条由指纹层报（`SpecError::HelloRetryWithoutKeyShare`，
    //    见 `crates/utls/src/hello/tests.rs`）—— 引擎侧到不了那个状态：`plan()` 本身
    //    就要求 key_share 组与引擎有交集。
    let client = chrome_70();
    let groups = engine_groups();
    let e = client
        .retry_plan(&HelloRetryRequestPlan {
            selected_group: Some(v::CURVE_P256),
            cookie: None,
            engine_groups: groups.clone(),
            resumption: None,
        })
        .unwrap_err();
    assert!(
        format!("{e}").contains("复用"),
        "报错该说清是「没有可复用的输入」：{e}"
    );

    // ② 服务器要一个 supported_groups 里没有的组 ⇒ 报错，不降级去发别的组。
    let client = chrome_70();
    let groups = engine_groups();
    client.plan(&plan_req(&groups)).unwrap();
    let e = client
        .retry_plan(&HelloRetryRequestPlan {
            selected_group: Some(0x0301), // 一个 Chrome-70 没声明过的组
            cookie: None,
            engine_groups: groups,
            resumption: None,
        })
        .unwrap_err();
    assert!(
        format!("{e}").contains("0x0301") || format!("{e}").contains("769"),
        "报错该点名那个组：{e}"
    );
}

/// 没实现 `retry_plan` 的供应者（默认实现）必须**响亮拒绝**，而不是发一条与第一飞
/// 不匹配的第二飞。这是 `FixedClientHello` 与任何旧实现的行为。
#[test]
fn the_default_retry_plan_refuses() {
    use rustls::client::{FixedClientHello, HelloRetryRequestPlan, SuppliesClientHello};

    let fixed = FixedClientHello(Default::default());
    let e = fixed
        .retry_plan(&HelloRetryRequestPlan {
            selected_group: Some(v::CURVE_P256),
            cookie: None,
            engine_groups: Vec::new(),
            resumption: None,
        })
        .unwrap_err();
    assert!(
        format!("{e}").contains("retry_plan"),
        "默认实现该说清是「没实现 retry_plan」：{e}"
    );
}

/// 有会话可复用、但 spec 里**没有** PSK 槽位 ⇒ 明确报错，而不是悄悄补一条扩展。
///
/// 补 `pre_shared_key` 会改指纹，而改指纹必须由调用方显式要求（uTLS 的
/// `Config.AlwaysIncludePSK`，本仓 `ClientHelloSpec::always_add_psk`）。
#[test]
fn a_preset_without_a_psk_slot_is_refused_rather_than_quietly_extended() {
    let client = chrome_70(); // Chrome-70 的 spec 里没有 PSK 槽位
    let groups = engine_groups();
    let err = client
        .plan(&PlanRequest {
            groups: groups.clone(),
            resumption: Some(offer()),
        })
        .unwrap_err();
    let text = format!("{err}");
    assert!(
        text.contains("pre_shared_key") && text.contains("always_add_psk"),
        "报错该说清是「没有 PSK 槽位」并指路 AlwaysIncludePSK：{text}"
    );
}

/// 有槽位时：PSK 被填成「identity = 服务端给的 ticket + 占位 binder」，并且
/// 引擎被告知 binder 该写在哪（RFC 8446 §4.2.11.2 的截断点）。
#[test]
fn a_psk_slot_is_filled_from_the_offer_and_the_binder_slot_is_reported() {
    let spec = ClientHelloSpec::from_preset(ClientHelloId::ChromePsk(100)).unwrap();
    let client = FingerprintClient::new(spec, provider()).with_client_random([0u8; 32]);
    let groups = engine_groups();
    let plan = client
        .plan(&PlanRequest {
            groups: groups.clone(),
            resumption: Some(offer()),
        })
        .unwrap();

    let bytes = plan.client_hello.clone().unwrap();
    let slot = plan.psk_binder.expect("该报告 binder 的位置");
    assert_eq!(slot.binder_len, 32, "SHA-256 的 binder 是 32 字节");
    // 截断点必须正好落在 binders 长度字段之前：`binders_len(2) + binder_len(1) + 32`
    // 之后就是 hello 的末尾（PSK 是最后一条扩展）。
    assert_eq!(bytes.len() - slot.truncated_len, 2 + 1 + 32);
    // 那条 identity 就是我们给的 ticket，且 binder 还是全零占位（真值由引擎写）。
    let body = &bytes[slot.truncated_len..];
    assert_eq!(
        body[0..2],
        [0, 33],
        "binders 长度 = 1 + 32（含 binder 自己的长度字节）"
    );
    assert_eq!(body[2], 32, "binder 长度字段");
    assert!(body[3..].iter().all(|b| *b == 0), "此时该是全零占位");

    // 换一个**没有**会话的请求：槽位不被填，也不报 binder 位置。
    let plain = client.plan(&plan_req(&groups)).unwrap();
    assert!(plain.psk_binder.is_none());
    assert_ne!(
        plain.client_hello.unwrap().len(),
        bytes.len(),
        "两次的字节该不同"
    );
}
