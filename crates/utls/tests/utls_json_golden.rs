//! **上游 `ClientHelloSpec` JSON golden 与我们预设的对账** ——
//! uTLS `u_clienthello_json_test.go` 那一族判据的等价物。
//!
//! 上游的判法：把 `testdata/ClientHello-JSON-*.json` 反解成 spec，与
//! `utlsIdToSpec(preset)` **逐字段**比（cipher suites、compression methods、
//! 扩展逐条；padding 因为带函数成员，只比 `PaddingLen` / `WillPad`）。
//! 我们同形：[`utls::json::spec_from_str`] 反解出的 spec 与
//! `ClientHelloSpec::from_preset(id)` 比 **JSON 可见的三个字段**
//! （`cipher_suites` / `compression_methods` / `extensions` —— 模型级 `PartialEq`，
//! GREASE 两边都是占位符，`KeyShare::reuse` 两边都是 `None`）。
//!
//! # 顺带补上的预设
//!
//! `Ios(14)` 是为这四份 golden 补的（此前返回 `PresetUnavailable`）——
//! 它没有独立的其他判据来源，所以这份对账**就是**它的主判据。
//!
//! # 本判据同时挡住的两类错
//!
//! 1. **我们抄错了预设**（名字表/顺序/码点错一处就红）；
//! 2. **JSON 模块放宽了**（比如静默丢一条扩展、把 GREASE 当具体值）——
//!    四份 golden 的每一份都红。
//!
//! # 不比的字段（以及为什么这不是缺口）
//!
//! `legacy_version` / `session_id` / `variability` 不在 JSON 格式里 —— 上游同样
//! 不存（它们来自 `ClientHelloID` 与 config，见 `utls::json` 模块头）。
//! 反解填充的默认值有独立断言。

use utls::hello::{ClientHelloId, ClientHelloSpec, SessionId, Variability};
use utls::json::spec_from_str;

const CHROME_102: &str = include_str!("fixtures/utls-json/ClientHello-JSON-Chrome102.json");
const FIREFOX_105: &str = include_str!("fixtures/utls-json/ClientHello-JSON-Firefox105.json");
const IOS_14: &str = include_str!("fixtures/utls-json/ClientHello-JSON-iOS14.json");
const EDGE_106: &str = include_str!("fixtures/utls-json/ClientHello-JSON-Edge106.json");

/// 对账本体：JSON 反解 vs `from_preset`，只比 JSON **可见**的字段。
fn assert_json_matches_preset(json_text: &str, id: ClientHelloId) {
    let from_json = spec_from_str(json_text).unwrap_or_else(|e| panic!("{id}: 反解失败：{e}"));
    let from_preset = ClientHelloSpec::from_preset(id).unwrap_or_else(|e| panic!("{id}: {e}"));

    assert_eq!(
        from_json.legacy_version, from_preset.legacy_version,
        "{id}: legacy_version（两边都取 uTLS 的固定 0x0303）"
    );
    assert_eq!(
        from_json.cipher_suites, from_preset.cipher_suites,
        "{id}: 密码套件（含顺序与 GREASE 占位符的位置）"
    );
    assert_eq!(
        from_json.compression_methods, from_preset.compression_methods,
        "{id}: 压缩方法"
    );
    assert_eq!(
        from_json.extensions, from_preset.extensions,
        "{id}: 扩展逐条（类型、顺序、体；GREASE 两边都是占位符）"
    );

    // 不可从 JSON 表达的字段：反解侧填的是文档写明的默认值，
    // 预设侧各是各的 —— 这条断言防止有人误以为它们参与了对账。
    assert!(matches!(from_json.session_id, SessionId::Random(32)));
    assert_eq!(from_json.variability, Variability::Stable);
}

#[test]
fn chrome_102_json_matches_the_preset() {
    assert_json_matches_preset(CHROME_102, ClientHelloId::Chrome(102));
}

#[test]
fn firefox_105_json_matches_the_preset() {
    assert_json_matches_preset(FIREFOX_105, ClientHelloId::Firefox(105));
}

#[test]
fn ios_14_json_matches_the_preset() {
    // 这条是 Ios(14) 预设的**主判据**：它就是为这份 golden 而实现的。
    assert_json_matches_preset(IOS_14, ClientHelloId::Ios(14));
}

#[test]
fn edge_106_json_matches_the_preset() {
    assert_json_matches_preset(EDGE_106, ClientHelloId::Edge(106));
}
