//! QUIC 传输参数的**编码层** —— uTLS `u_quic_transport_parameters.go` 的移植。
//!
//! # 它在指纹里的位置
//!
//! TLS over QUIC 时，传输参数**就是 ClientHello 里的一个扩展**
//! （uTLS 的注释说得很直白：用 preset 时 `SetTransportParameters` **不**走
//! `quic.transportParams`，而是走 `QUICTransportParametersExtension`）。
//! 所以这一层不是「QUIC 的连接 API」，而是**指纹的一部分** ——
//! 与 `hello` 模块同属一层，也遵守同一套规矩：
//!
//! - **同 seed ⇒ 逐字节相同**（HRR 第二飞要复现第一飞，这条不能破）；
//! - 随机量来自**每连接的 seed**，而不是这里另起一股 crypto/rand ——
//!   这与 uTLS 有一个**刻意的差别**：上游的 `GREASETransportParameter` /
//!   `GetGREASEVersion` 每次 `Value()` 都从系统熵新抽（它的注释让你「每连接
//!   造一个新参数」来变化）。我们改由 seed 驱动：**跨连接**照样每条不同
//!   （seed 每连接新取），**同连接**可复现（HRR 需要）。上游做不到后者，
//!   我们做不到前者的「连接内重复调用也变」—— 见各方法的判据。
//! - 抽取顺序是**线序可推**的（先 ID 后载荷），与 `encode.rs` 的 GREASE-ECH 同一条纪律。
//!
//! # 判据
//!
//! 本模块的单元测试（文件底部）移植了上游的三条判据：
//! `TestMarshal`（Firefox 参数集的 golden bytes，逐字节）、
//! `TestGetGREASEVersion` / `TestVersionGREASEConstantIsReserved`
//! （4096 次抽样必须都是 `0x?a?a?a?a` 且高位不全同 —— 上游加它是因为底层实现
//! 曾漏掩码，让这个参数变成「不是真浏览器」的可靠信号）、
//! `TestVersionInformationGREASESubstitution`（哨兵逐次替换、非哨兵原样、结构里仍是哨兵）。

use crate::hello::SpecError;
use crate::hello::stream::Stream;

/// RFC 9000 §16 的变长整数（**最短**编码：`0b00` 1 字节 / `0b01` 2 / `0b10` 4 / `0b11` 8）。
pub fn varint(v: u64) -> Vec<u8> {
    let (prefix, len) = if v < 1 << 6 {
        (0b00, 1)
    } else if v < 1 << 14 {
        (0b01, 2)
    } else if v < 1 << 30 {
        (0b10, 4)
    } else {
        (0b11, 8)
    };
    let mut out = Vec::with_capacity(len);
    for i in (0..len).rev() {
        out.push((v >> (i * 8)) as u8);
    }
    out[0] |= prefix << (8 - 2);
    out
}

/// 上游的版本常量（`u_quic_transport_parameters.go:268-278`）。
pub const VERSION_NEGOTIATION: u32 = 0x0000_0000;
pub const VERSION_1: u32 = 0x0000_0001;
pub const VERSION_2: u32 = 0x6b33_43cf;
/// 「这里放一个保留版本」的**占位符**，不是要原样发出去的版本：
/// 序列化时被 [`VersionInformation::get_grease_version`] 的新鲜抽取替换。
pub const VERSION_GREASE: u32 = 0x0a0a_0a0a;

/// version_information 参数的 ID：RFC 9368 的 `0x11`，或草案的旧 ID。
const VERSION_INFORMATION_ID: u64 = 0x11;
const VERSION_INFORMATION_LEGACY_ID: u64 = 0xff73db;

/// version_information（RFC 9368）：客户端选定的版本在前，后面是它愿意接受的每个版本。
///
/// Chrome 发送时把一个 GREASE 版本放在 available 列表的最前面。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInformation {
    /// 正在建立的这条连接用的版本。（拼写 `chosen` 是本仓的；上游字段叫
    /// `ChoosenVersion` —— 那是它的笔误，注释里自己承认。）
    pub chosen_version: u32,
    /// 愿意接受的版本，**按线序**。[`VERSION_GREASE`] 是占位符：`value()` 每次调用
    /// 都把它换成一次新鲜的保留版本，其余条目原样。
    pub available_versions: Vec<u32>,
    /// `true` ⇒ 用草案的旧 ID（`0xff73db`）而不是 RFC 的 `0x11`。
    pub legacy_id: bool,
}

impl VersionInformation {
    pub fn id(&self) -> u64 {
        if self.legacy_id {
            VERSION_INFORMATION_LEGACY_ID
        } else {
            VERSION_INFORMATION_ID
        }
    }

    /// 参数体：`chosen(4) || available(4)*`。每次调用都重抽哨兵 ——
    /// **结构体里的哨兵不动**（上游的判据专门验这条）。
    pub(crate) fn value(&self, stream: &mut Stream) -> Vec<u8> {
        let mut b = Vec::with_capacity(4 + 4 * self.available_versions.len());
        b.extend_from_slice(&self.chosen_version.to_be_bytes());
        for &version in &self.available_versions {
            let v = if version == VERSION_GREASE {
                self.get_grease_version(stream)
            } else {
                version
            };
            b.extend_from_slice(&v.to_be_bytes());
        }
        b
    }

    /// 一个符合 `0x?a?a?a?a`（RFC 9000 §15）的保留版本。
    ///
    /// ⚠️ **低半位必须先掩掉再置上**：只 OR 的话，随机位留在底下，
    /// 一个低半位为 0x5 的抽签会变成 0xf —— 根本不是 GREASE 值。
    /// 上游的判据注释写明：加掩码之前 256 次抽签只有 1 次是合法的。
    /// （上游在系统熵失败时回落到固定的 [`VERSION_GREASE`]；我们的流不会失败，
    /// 所以那条回落路径在本仓**不存在** —— 一个固定的「GREASE」版本本身就是指纹。）
    pub(crate) fn get_grease_version(&self, stream: &mut Stream) -> u32 {
        let mut b = [0u8; 4];
        stream.fill(&mut b);
        u32::from_be_bytes(b) & 0xf0f0_f0f0 | 0x0a0a_0a0a
    }
}

/// 保留（GREASE）传输参数的 ID 族：`31*N + 27`（RFC 9000 §22.3）。
pub fn is_grease_id(id: u64) -> bool {
    id >= 27 && (id - 27).is_multiple_of(31)
}

/// `GetGREASEID` 的乘数上界（上游 `GREASE_MAX_MULTIPLIER`）：
/// 保证 `27 + m*31` 仍是 `0x3FFF_FFFF_FFFF_FFFF` 以内的合法值。
pub const GREASE_MAX_MULTIPLIER: u64 = (0x3fff_ffff_ffff_ffff - 27) / 31;

/// 一个随机的合法 GREASE 参数 ID。**拒绝采样**（不是取模）——
/// 取模会在余数区造成可测的偏置，而 ID 本身就是指纹。
pub(crate) fn get_grease_id(stream: &mut Stream) -> u64 {
    27 + random_below(stream, GREASE_MAX_MULTIPLIER) * 31
}

fn random_below(stream: &mut Stream, max: u64) -> u64 {
    debug_assert!(max > 0);
    let zone = u64::MAX - (u64::MAX % max);
    loop {
        let mut b = [0u8; 8];
        stream.fill(&mut b);
        let x = u64::from_le_bytes(b);
        if x < zone {
            return x % max;
        }
    }
}

/// 一个 QUIC 传输参数。uTLS 用一个 trait（`ID()` / `Value()`），这里是一个枚举 ——
/// 语义一一对应，`Value()` 返回**长度字段之后**要写的字节。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportParameter {
    MaxIdleTimeout(u64),
    MaxUdpPayloadSize(u64),
    InitialMaxData(u64),
    InitialMaxStreamDataBidiLocal(u64),
    InitialMaxStreamDataBidiRemote(u64),
    InitialMaxStreamDataUni(u64),
    InitialMaxStreamsBidi(u64),
    InitialMaxStreamsUni(u64),
    MaxAckDelay(u64),
    /// 体**必须**为空（RFC 9000 §18.1）。
    DisableActiveMigration,
    ActiveConnectionIdLimit(u64),
    /// 为空时上游会填 Initial 包用的 Connection ID；这里是纯编码层，由调用方给。
    InitialSourceConnectionId(Vec<u8>),
    VersionInformation(VersionInformation),
    /// 原样字节（Google 的 `google_quic_version` 一类就用它发）。
    Padding(Vec<u8>),
    MaxDatagramFrameSize(u64),
    /// 体**必须**为空。
    GreaseQuicBit,
    /// 保留（GREASE）参数：ID 形如 `31N+27`，载荷是无意义字节。
    /// 抽取是**惰性并缓存**的（上游同款）：`id()` 抽了 ID 就记进 `id_override`，
    /// `value()` 抽了字节就记进 `value_override` —— 之后重用同一个值**重复同一串字节**，
    /// 所以要每连接造新的（上游注释原话）。
    Grease {
        /// 合法的 GREASE ID 就用它；否则惰性抽取后记在这里。
        id_override: Option<u64>,
        /// `value_override` 为空时按这个长度抽随机字节。
        length: u16,
        value_override: Vec<u8>,
    },
    /// 逃生口：任何没有专名的参数，`id` + `value` 原样发
    /// （`value` 必须是**已按 RFC 编码**的字节 —— 数值参数要自己先变长编码）。
    Fake {
        id: u64,
        value: Vec<u8>,
    },
}

impl TransportParameter {
    /// 线上的参数 ID。`Grease` 在这里惰性抽取并缓存。
    fn id(&mut self, stream: &mut Stream) -> Result<u64, SpecError> {
        match self {
            TransportParameter::Grease { id_override, .. } => Ok(match *id_override {
                Some(id) if is_grease_id(id) => id,
                _ => {
                    let id = get_grease_id(stream);
                    *id_override = Some(id);
                    id
                }
            }),
            TransportParameter::Fake { id, .. } => {
                // 上游在这里 panic；本 crate 的习惯是把「发不出去」交成错误。
                if *id == 0 {
                    return Err(SpecError::QuicFakeParameterWithoutId);
                }
                Ok(*id)
            }
            other => Ok(other.named_id()),
        }
    }

    fn named_id(&self) -> u64 {
        match self {
            TransportParameter::MaxIdleTimeout(_) => 0x1,
            TransportParameter::MaxUdpPayloadSize(_) => 0x3,
            TransportParameter::InitialMaxData(_) => 0x4,
            TransportParameter::InitialMaxStreamDataBidiLocal(_) => 0x5,
            TransportParameter::InitialMaxStreamDataBidiRemote(_) => 0x6,
            TransportParameter::InitialMaxStreamDataUni(_) => 0x7,
            TransportParameter::InitialMaxStreamsBidi(_) => 0x8,
            TransportParameter::InitialMaxStreamsUni(_) => 0x9,
            TransportParameter::MaxAckDelay(_) => 0xb,
            TransportParameter::DisableActiveMigration => 0xc,
            TransportParameter::ActiveConnectionIdLimit(_) => 0xe,
            TransportParameter::InitialSourceConnectionId(_) => 0xf,
            TransportParameter::VersionInformation(vi) => vi.id(),
            TransportParameter::Padding(_) => 0x15,
            TransportParameter::MaxDatagramFrameSize(_) => 0x20,
            TransportParameter::GreaseQuicBit => 0x2ab2,
            TransportParameter::Grease { .. } | TransportParameter::Fake { .. } => {
                unreachable!("这两个变体在 id() 的前面分支处理")
            }
        }
    }

    /// 长度字段之后的体。`Grease` 在这里惰性填随机字节并缓存。
    fn value(&mut self, stream: &mut Stream) -> Vec<u8> {
        match self {
            TransportParameter::Grease {
                value_override,
                length,
                ..
            } => {
                if value_override.is_empty() {
                    let mut b = vec![0u8; *length as usize];
                    stream.fill(&mut b);
                    *value_override = b;
                }
                value_override.clone()
            }
            TransportParameter::Fake { value, .. } => value.clone(),
            other => other.named_value(stream),
        }
    }

    fn named_value(&self, stream: &mut Stream) -> Vec<u8> {
        match self {
            TransportParameter::MaxIdleTimeout(v)
            | TransportParameter::MaxUdpPayloadSize(v)
            | TransportParameter::InitialMaxData(v)
            | TransportParameter::InitialMaxStreamDataBidiLocal(v)
            | TransportParameter::InitialMaxStreamDataBidiRemote(v)
            | TransportParameter::InitialMaxStreamDataUni(v)
            | TransportParameter::InitialMaxStreamsBidi(v)
            | TransportParameter::InitialMaxStreamsUni(v)
            | TransportParameter::MaxAckDelay(v)
            | TransportParameter::ActiveConnectionIdLimit(v)
            | TransportParameter::MaxDatagramFrameSize(v) => varint(*v),
            TransportParameter::DisableActiveMigration | TransportParameter::GreaseQuicBit => {
                Vec::new()
            }
            TransportParameter::InitialSourceConnectionId(b) | TransportParameter::Padding(b) => {
                b.clone()
            }
            TransportParameter::VersionInformation(vi) => vi.value(stream),
            TransportParameter::Grease { .. } | TransportParameter::Fake { .. } => {
                unreachable!("这两个变体在 value() 的前面分支处理")
            }
        }
    }
}

/// 一份**有序**的传输参数列表 —— 切片顺序就是线序。
///
/// RFC 9000 §7.4 允许客户端任意排序，而真实客户端各不相同
/// （Chrome 每次握手随机化），所以**顺序本身就是指纹信号**。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransportParameters(pub Vec<TransportParameter>);

impl TransportParameters {
    /// 序列化成扩展体：每个参数 = `varint(ID) || varint(len) || value`。
    ///
    /// 随机量来自 **seed**（每连接新取）：同 seed ⇒ 逐字节相同（HRR 第二飞要复现），
    /// 换 seed ⇒ GREASE 的 ID / 版本 / 载荷全部不同。流用
    /// [`Stream::for_transport_parameters`] 与 hello 那条**分域**，
    /// 免得这里的抽取与 hello 里的 GREASE 值相关。
    ///
    /// ⚠️ 会**消费可变性**：`Grease` 的惰性抽取要缓存进参数本身（上游同款）。
    pub fn marshal(&mut self, seed: &[u8; 32]) -> Result<Vec<u8>, SpecError> {
        let mut stream = Stream::for_transport_parameters(seed);
        let mut b = Vec::new();
        for tp in &mut self.0 {
            let id = tp.id(&mut stream)?;
            let value = tp.value(&mut stream);
            b.extend_from_slice(&varint(id));
            b.extend_from_slice(&varint(value.len() as u64));
            b.extend_from_slice(&value);
        }
        Ok(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(seed: u8) -> Stream {
        Stream::new(&[seed; 32])
    }

    /// 上游 `TestMarshal`（`u_quic_transport_parameters_test.go:6`）的 Firefox 参数集，
    /// 期望字节逐字移植。**两边的 GREASE 参数都带 override ⇒ 不发生任何抽取**，
    /// 所以这一条是纯确定性的对账。
    #[test]
    fn firefox_parameter_set_matches_the_upstream_golden_bytes() {
        let mut tps = TransportParameters(vec![
            TransportParameter::InitialMaxStreamDataBidiRemote(0x10_0000),
            TransportParameter::InitialMaxStreamsBidi(16),
            TransportParameter::MaxDatagramFrameSize(1200),
            TransportParameter::MaxIdleTimeout(30_000),
            TransportParameter::ActiveConnectionIdLimit(8),
            TransportParameter::GreaseQuicBit,
            TransportParameter::VersionInformation(VersionInformation {
                chosen_version: VERSION_1,
                available_versions: vec![0x8aca_faea, 0x0000_0001],
                legacy_id: true,
            }),
            TransportParameter::InitialMaxStreamsUni(16),
            TransportParameter::Grease {
                id_override: Some(0xff02_de1a),
                length: 0,
                value_override: vec![0x43, 0xe8],
            },
            TransportParameter::InitialMaxStreamDataBidiLocal(0xc0_0000),
            TransportParameter::InitialMaxStreamDataUni(0x10_0000),
            TransportParameter::InitialSourceConnectionId(vec![0x53, 0xf0, 0xb2]),
            TransportParameter::MaxAckDelay(20),
            TransportParameter::InitialMaxData(0x180_0000),
            TransportParameter::DisableActiveMigration,
        ]);
        let got = tps.marshal(&[1; 32]).expect("全部带 override，不该失败");
        let want: Vec<u8> = [
            0x06, 0x04, 0x80, 0x10, 0x00, 0x00, 0x08, 0x01, 0x10, 0x20, 0x02, 0x44, 0xb0, 0x01,
            0x04, 0x80, 0x00, 0x75, 0x30, 0x0e, 0x01, 0x08, 0x6a, 0xb2, 0x00, 0x80, 0xff, 0x73,
            0xdb, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x8a, 0xca, 0xfa, 0xea, 0x00, 0x00, 0x00, 0x01,
            0x09, 0x01, 0x10, 0xc0, 0x00, 0x00, 0x00, 0xff, 0x02, 0xde, 0x1a, 0x02, 0x43, 0xe8,
            0x05, 0x04, 0x80, 0xc0, 0x00, 0x00, 0x07, 0x04, 0x80, 0x10, 0x00, 0x00, 0x0f, 0x03,
            0x53, 0xf0, 0xb2, 0x0b, 0x01, 0x14, 0x04, 0x04, 0x81, 0x80, 0x00, 0x00, 0x0c, 0x00,
        ]
        .to_vec();
        assert_eq!(got, want, "Firefox 参数集的线字节该与上游 golden 完全一致");
    }

    /// 上游 `TestGetGREASEVersion`：4096 次抽样，每个都必须是 `0x?a?a?a?a`，
    /// 且高位（不被掩码钉住的那些位）不能只有少数几个值 ——
    /// 「固定返回一个值」虽是合法 GREASE，却**本身就是指纹**。
    #[test]
    fn grease_version_draws_match_the_reserved_pattern_and_vary() {
        let is_reserved = |v: u32| v & 0x0f0f_0f0f == 0x0a0a_0a0a;
        let vi = VersionInformation {
            chosen_version: VERSION_1,
            available_versions: Vec::new(),
            legacy_id: false,
        };
        let mut s = stream(9);
        let mut high_nibbles = std::collections::BTreeSet::new();
        for _ in 0..4096 {
            let v = vi.get_grease_version(&mut s);
            assert!(
                is_reserved(v),
                "GetGREASEVersion() = {v:#010x}，不是 0x?a?a?a?a —— 低半位没掩干净"
            );
            high_nibbles.insert(v & 0xf0f0_f0f0);
        }
        assert!(
            high_nibbles.len() >= 2048,
            "4096 次抽签只有 {} 个不同的高位 —— 抽取在重复自己",
            high_nibbles.len()
        );
    }

    /// 上游 `TestVersionInformationGREASESubstitution`：哨兵逐次替换、
    /// 非哨兵原样、**结构体里的哨兵不动**。
    #[test]
    fn version_information_substitutes_the_sentinel_per_call() {
        let vi = VersionInformation {
            chosen_version: VERSION_1,
            available_versions: vec![VERSION_GREASE, VERSION_1, VERSION_2],
            legacy_id: false,
        };
        let is_reserved = |v: u32| v & 0x0f0f_0f0f == 0x0a0a_0a0a;
        let mut s = stream(11);
        let read_versions = |s: &mut Stream| -> Vec<u32> {
            let val = vi.value(s);
            let (chunks, rest) = val.as_chunks::<4>();
            assert!(
                rest.is_empty(),
                "体长该是 4 的整数倍，余下 {} 字节",
                rest.len()
            );
            chunks.iter().map(|c| u32::from_be_bytes(*c)).collect()
        };

        let first = read_versions(&mut s);
        assert_eq!(first.len(), 4, "chosen + 3 个 available");
        assert_eq!(first[0], VERSION_1, "chosen 版本在体首");
        assert!(
            is_reserved(first[1]),
            "被替换进去的该是保留版本：{:08x}",
            first[1]
        );
        assert_eq!(
            (first[2], first[3]),
            (VERSION_1, VERSION_2),
            "非哨兵的条目不许被改写"
        );

        // 哨兵逐次重抽：允许极小概率撞车（自由位 2^28），给几次机会。
        let mut differed = false;
        for _ in 0..8 {
            if read_versions(&mut s)[1] != first[1] {
                differed = true;
                break;
            }
        }
        assert!(
            differed,
            "每次调用都返回同一个 GREASE 版本 —— 那本身就是指纹"
        );

        // 结构体里的哨兵必须还在：后面的调用继续替换。
        assert_eq!(
            vi.available_versions[0], VERSION_GREASE,
            "哨兵不许被原地改写"
        );
    }

    /// 上游 `TestVersionGREASEConstantIsReserved`：哨兵/回落值本身必须合法。
    #[test]
    fn the_grease_sentinel_is_itself_a_reserved_version() {
        // 通过一个真实参数走到这条值：哨兵若不是保留版本，下面的替换判据就没了意义。
        let vi = VersionInformation {
            chosen_version: VERSION_1,
            available_versions: vec![VERSION_GREASE],
            legacy_id: false,
        };
        let mut s = stream(13);
        let v = vi.value(&mut s);
        let sentinel = u32::from_be_bytes(v[4..8].try_into().unwrap());
        assert!(
            sentinel & 0x0f0f_0f0f == 0x0a0a_0a0a,
            "哨兵 {sentinel:#010x} 不是保留版本"
        );
        assert_eq!(u32::from_be_bytes(v[0..4].try_into().unwrap()), VERSION_1);
    }

    /// GREASE 参数 ID 的两条性质：抽出来的**一定**合法；给定的合法 override 原样用。
    #[test]
    fn grease_parameter_ids_are_always_valid_and_overrides_are_honored() {
        let mut s = stream(3);
        for _ in 0..512 {
            let id = get_grease_id(&mut s);
            assert!(is_grease_id(id), "抽出的 {id} 不是 31N+27 形");
        }
        // override 合法 ⇒ 原样用（golden bytes 那条已经判了 0xff02de1a 这一支）；
        // override 不合法 ⇒ 惰性替换成一个合法的。
        let mut bad = TransportParameter::Grease {
            id_override: Some(0xff02_de19), // 比 golden 那个少 1，不是 31N+27
            length: 0,
            value_override: vec![0x00],
        };
        let id = bad.id(&mut s).expect("Grease 的 id 不会失败");
        assert!(
            is_grease_id(id),
            "不合法的 override 该被替换成合法 ID，得到 {id}"
        );
        assert_ne!(id, 0xff02_de19);
    }

    /// `Fake` 参数没有 ID ⇒ 明确报错（上游 panic，本 crate 把「发不出去」交成错误）。
    #[test]
    fn a_fake_parameter_without_an_id_is_an_error_not_a_silent_zero() {
        let mut tps = TransportParameters(vec![TransportParameter::Fake {
            id: 0,
            value: vec![0x01],
        }]);
        let err = tps.marshal(&[5; 32]).expect_err("参数 0 不得静默上线");
        assert!(
            err.to_string().contains("Fake") || err.to_string().contains("传输参数"),
            "错误信息该说清楚是哪一类问题：{err}"
        );
    }

    /// varint 的最短编码（RFC 9000 §16）：这条挡的是「用 8 字节形式发一个小数」这类错。
    #[test]
    fn varint_uses_the_shortest_form() {
        assert_eq!(varint(0), vec![0x00]);
        assert_eq!(varint(63), vec![0x3f]);
        assert_eq!(varint(64), vec![0x40, 0x40]);
        assert_eq!(varint(16_383), vec![0x7f, 0xff]);
        assert_eq!(varint(16_384), vec![0x80, 0x00, 0x40, 0x00]);
        assert_eq!(varint(30_000), vec![0x80, 0x00, 0x75, 0x30]);
        assert_eq!(varint(1_073_741_823), vec![0xbf, 0xff, 0xff, 0xff]);
        assert_eq!(
            varint(1_073_741_824),
            vec![0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]
        );
        // 回读：每个样本都要能无损读回。
        for v in [0u64, 1, 63, 64, 1000, 16_383, 16_384, 30_000, 0xff02_de1a] {
            let e = varint(v);
            let (val, used) = read_varint(&e).expect("可读");
            assert_eq!((val, used), (v, e.len()), "{v} 的编码回读不一致");
        }
    }

    /// 测试用的最小变长整数读取器（生产侧目前只编码；读取留给引擎那半边）。
    fn read_varint(b: &[u8]) -> Option<(u64, usize)> {
        if b.is_empty() {
            return None;
        }
        let len = 1usize << (b[0] >> 6);
        if b.len() < len {
            return None;
        }
        let mut v = u64::from(b[0] & 0x3f);
        for byte in &b[1..len] {
            v = (v << 8) | u64::from(*byte);
        }
        Some((v, len))
    }
}
