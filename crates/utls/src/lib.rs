//! uTLS-rs —— 纯 Rust 复刻 [`refraction-networking/utls`]。
//!
//! 本 crate 的目标与 uTLS 一致：让 ClientHello 成为**可命名、可复现、可验证**的东西。
//! 但分层与 uTLS 不同 —— 这里刻意把「指纹」与「引擎」分开：
//!
//! - [`hello`]：ClientHello 的数据模型与序列化。**纯计算，不引用任何 TLS 引擎的类型。**
//!   这是本项目的价值所在，也是唯一能脱离网络独立验证的部分。
//! - 引擎层（尚未落地）：一个 vendored 的 rustls fork，把 [`hello`] 产出的字节接进真实握手。
//!
//! 为什么这样切：rustls 在两年内两次重构内部扩展表示，若把它的类型写进本文档的公开接口，
//! 每次上游发版都会击穿所有调用方。所以引擎那侧被压成一个薄适配层，delta 只剩插桩点。
//! 详见 `README.md` 与 `STATE.md`。
//!
//! [`refraction-networking/utls`]: https://github.com/refraction-networking/utls

pub mod hello;
pub mod ja3;
pub mod quic;
pub mod values;

pub use hello::{ClientHello, ClientHelloId, ClientHelloSpec, HandshakeInputs};
pub use ja3::Ja3;
