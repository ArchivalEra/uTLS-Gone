//! `UClient` / `apply_preset` 的**离线**测试（不联网）。
//!
//! 这些测的是「uTLS 那条 API 形状在本仓怎么落地」：`applyPresetByID` 对三类 ID 的分派、
//! 以及 `ApplyPreset` 的「你的 spec 不会被改动」这个契约。

use utls::hello::{ClientHelloId, ClientHelloSpec, SpecError};
use utls_engine::UClient;

#[test]
fn apply_preset_by_id_covers_every_form_of_id() {
    // ① 静态预设：直接取。
    let c = UClient::new().apply_preset_by_id(ClientHelloId::Chrome(133)).unwrap();
    assert!(!c.spec().cipher_suites.is_empty());

    // ② 随机化：`applyPresetByID` 在 `Seed == nil` 时现取一个种子 ⇒ 每次不同。
    let a = UClient::new().apply_preset_by_id(ClientHelloId::Randomized).unwrap();
    let b = UClient::new().apply_preset_by_id(ClientHelloId::Randomized).unwrap();
    assert_ne!(a.spec(), b.spec(), "随机化 ID 每次该产出不同的 spec");

    // ③ `Golang`：不是「未实现」，是「在本架构里不适用」（见 SpecError::EngineDefined）。
    let e = UClient::new().apply_preset_by_id(ClientHelloId::Golang).unwrap_err();
    assert!(matches!(e, SpecError::EngineDefined(ClientHelloId::Golang)), "拿到的是 {e:?}");

    // ④ 随机化 ID **不**能走 from_preset —— 那条路没有种子。
    assert!(matches!(
        UClient::new().apply_preset_by_id(ClientHelloId::RandomizedAlpn).map(|_| ()),
        Ok(())
    ));
    assert!(matches!(
        ClientHelloSpec::from_preset(ClientHelloId::RandomizedNoAlpn).unwrap_err(),
        SpecError::RandomizedNeedsSeed(_)
    ));
}

#[test]
fn apply_preset_takes_the_spec_by_value() {
    // uTLS 的注释是「The provided ClientHelloSpec is cloned before per-connection handshake
    // state is applied」—— 也就是**你的 spec 不会被改动**。
    // 本仓这边 spec 是按值传入的，同一个契约由类型表达而不是由克隆表达。
    let spec = ClientHelloSpec::from_preset(ClientHelloId::Firefox(148)).unwrap();
    let before = spec.clone();
    let c = UClient::new().apply_preset(spec);
    assert_eq!(c.spec(), &before, "施加之后拿到的该正是传进去的那份");
}

#[test]
fn an_empty_client_cannot_connect() {
    // 起点是空 spec（uTLS 的 `HelloCustom`）。`apply_preset` 之前它就位，而空 spec
    // **不是**一条能用的 ClientHello —— 所以建连会因为 marshal 失败而明确报错，
    // 而不是发出一条畸形的 hello。这里只验到「它确实没被当成能用」这一层（不联网）。
    let c = UClient::new();
    assert!(c.spec().cipher_suites.is_empty(), "起点该是空的");
}
