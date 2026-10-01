//! ClientHello 的手写序列化器。
//!
//! 为什么手写而不是用现成库：整件事的难点就是**顺序与长度字段的精确控制**，
//! 而这恰好是「用库」会藏起来的部分。而且反解器就在这里旁边（`parse.rs`）——
//! 序列化与反解是一对互逆函数，必须一起改；把其中一个换成 derive 宏会让这对
//! 不变量散到两个地方，那就没有 locality 了。
//!
//! # 从 seed 抽取的**固定顺序**（改变它就是改变每条确定性输出）
//!
//! 1. GREASE 值集合（密码套件 / 支持组 / key_share / 支持版本 / 签名算法 / 两个扩展类型）
//! 2. `legacy_session_id`（当 `SessionId::Random`）
//! 3. 逐个 `GreaseEch` 扩展：**按线序**抽套件、config_id、封装密钥、载荷长度、载荷
//! 4. 扩展乱序的置换（当 `Variability::Shuffled`）
//!
//! 改这个顺序 = 改每条与 seed 绑定的输出。所以它必须是**读代码就能推出来**的那个顺序
//! （即线序），而不是某个「当时能用」的顺序。
//!
//! 客户端随机数**不在这里** —— 它由 [`HandshakeInputs::client_random`] 直接给出，
//! 生产路径上是 OS 熵。指纹的每连接变化与密码学随机数因此走两条路，互不污染。

use super::extensions;
use super::spec::{
    ClientHelloSpec, CodePoint, Extension, GreaseEchOptions, Padding, SessionId, SpecError,
    Variability,
};
use super::stream::Stream;
use super::{ClientHello, HandshakeInputs};
use crate::values as v;

/// 每连接的 GREASE 取值集合。
///
/// uTLS 按**类别**各取一个值，而不是按出现位置 —— 所以即使密码套件列表里
/// GREASE 出现在多处，它们也共用一个值。这里逐类复刻该语义。
struct GreaseSet {
    cipher: u16,
    group: u16,
    key_share: u16,
    version: u16,
    sig_alg: u16,
    ext: [u16; 2],
}

impl GreaseSet {
    fn draw(s: &mut Stream) -> Self {
        let cipher = s.grease();
        let group = s.grease();
        let key_share = s.grease();
        let version = s.grease();
        let sig_alg = s.grease();
        // 两个扩展 GREASE 值必须不同。uTLS 的做法是「seed 撞了就 XOR 0x1010」，
        // 而那个 XOR 作用在 **seed** 上（再经 GetBoringGREASEValue 映射成 0xωaωa）。
        // 直接在值上 XOR 会得到 0xωbωb —— 那不是一个合法 GREASE 值。这里改成
        // 「撞了就顺延」，等价、且保证产出的始终是合法 GREASE 值。
        let i0 = s.below(v::GREASE_VALUES.len() as u32) as usize;
        let mut i1 = s.below(v::GREASE_VALUES.len() as u32) as usize;
        if i1 == i0 {
            i1 = (i1 + 1) % v::GREASE_VALUES.len();
        }
        GreaseSet {
            cipher,
            group,
            key_share,
            version,
            sig_alg,
            ext: [v::GREASE_VALUES[i0], v::GREASE_VALUES[i1]],
        }
    }
}

/// 一个已解析（GREASE 已替换、体已算好）的扩展槽位。
#[derive(Clone)]
struct Resolved {
    ty: u16,
    body: Vec<u8>,
    /// 乱序时位置不动（GREASE / padding / PSK）。
    pinned: bool,
    /// 是否真的写进字节。
    ///
    /// 为什么需要它：uTLS 里「长度 0 的扩展」**在列表里、但不占字节**（`Len()` 返回 0）。
    /// 它仍然参与洗牌的那次抽取（洗牌按列表长度抽，只是跳过与它相关的交换）。
    /// 所以「窗口外的填充」与「空 PSK」都必须是**保留而不写**，不能从列表里删掉 ——
    /// 删掉会让后续抽取错位，而那种错在乱序预设上**看不见**（顺序不比、0 字节不改长度）。
    emit: bool,
}

pub(crate) fn marshal(
    spec: &ClientHelloSpec,
    inputs: &HandshakeInputs,
) -> Result<ClientHello, SpecError> {
    check_shape(spec)?;

    let mut stream = inputs.stream();
    let grease = GreaseSet::draw(&mut stream);

    // ── 1. legacy_session_id ────────────────────────────────────────────────
    let session_id = match &spec.session_id {
        SessionId::Empty => Vec::new(),
        SessionId::Fixed(b) => {
            if b.len() > 32 {
                return Err(SpecError::SessionIdTooLong(b.len()));
            }
            b.clone()
        }
        SessionId::Random(n) => {
            let n = (*n as usize).min(32);
            let mut out = vec![0u8; n];
            stream.fill(&mut out);
            out
        }
    };

    // ── 2. 解析扩展 ─────────────────────────────────────────────────────────
    let mut resolved: Vec<Resolved> = Vec::new();
    let mut grease_used = 0usize;
    let mut padding: Option<(usize, Padding)> = None;

    for ext in &spec.extensions {
        match ext {
            Extension::Grease => {
                let Some(&ty) = grease.ext.get(grease_used) else {
                    return Err(SpecError::TooManyGreaseExtensions(grease_used + 1));
                };
                // uTLS `u_parrots.go:3117-3127`：**第 1 个** GREASE 扩展体为空，
                // **第 2 个**体是 `[0]`，第 3 个直接报错（`at most 2 …`）。
                //
                // ⚠️ 这 1 个字节不进 JA3（JA3 只看扩展**类型**），所以它错了也不会让
                // 任何 JA3 对账变红 —— 只有**总长**对账能抓到。本仓就是这么抓到的：
                // Chrome 115_PQ 的总长比参照少 1 字节，而所有 JA3 字段都对得上。
                let body = if grease_used == 1 {
                    vec![0u8]
                } else {
                    Vec::new()
                };
                grease_used += 1;
                resolved.push(Resolved {
                    ty,
                    body,
                    pinned: true,
                    emit: true,
                });
            }
            Extension::Padding(p) => {
                if padding.is_some() {
                    return Err(SpecError::DuplicateExtension(v::EXT_PADDING));
                }
                padding = Some((resolved.len(), *p));
                resolved.push(Resolved {
                    ty: v::EXT_PADDING,
                    body: Vec::new(),
                    pinned: true,
                    emit: true,
                });
            }
            Extension::ServerName => {
                // 名字来源与「空则零字节」的规则见 `Extension::ServerName` 的说明。
                // `inputs.sni` 是 uTLS 的 `config.ServerName`：`None` 与 `Some("")` 同义
                // （Go 里都是空串），都落进「零字节但占位」那一支，**不是错误**。
                let host = hostname_in_sni(inputs.sni.as_deref().unwrap_or(""));
                if host.is_empty() {
                    // 零字节但**占着洗牌位**：见上面那条关于「长度 0 的扩展」的说明。
                    resolved.push(Resolved {
                        ty: v::EXT_SERVER_NAME,
                        body: Vec::new(),
                        pinned: false,
                        emit: false,
                    });
                } else {
                    resolved.push(Resolved {
                        ty: v::EXT_SERVER_NAME,
                        body: sni_body(&host)?,
                        pinned: false,
                        emit: true,
                    });
                }
            }
            Extension::Alpn(default) => {
                // `inputs.alpn` 覆盖预设的建议列表。两处都空 ⇒ **省略整个扩展**，
                // 而不是发一个空列表：两者指纹不同，而「省略」是真实浏览器在
                // 没有可谈协议时（以及 Go 在没设 NextProtos 时）的行为。
                let list: &[Vec<u8>] = if inputs.alpn.is_empty() {
                    default.as_slice()
                } else {
                    &inputs.alpn
                };
                if list.is_empty() {
                    continue;
                }
                resolved.push(Resolved {
                    ty: v::EXT_ALPN,
                    body: alpn_body(list)?,
                    pinned: false,
                    emit: true,
                });
            }
            Extension::SupportedVersions(cps) => {
                let vals = resolve_list(cps, grease.version);
                resolved.push(Resolved {
                    ty: v::EXT_SUPPORTED_VERSIONS,
                    body: supported_versions_body(&vals)?,
                    pinned: false,
                    emit: true,
                });
            }
            Extension::SupportedGroups(cps) => {
                let vals = resolve_list(cps, grease.group);
                resolved.push(Resolved {
                    ty: v::EXT_SUPPORTED_GROUPS,
                    body: u16_list_body(&vals)?,
                    pinned: false,
                    emit: true,
                });
            }
            Extension::SignatureAlgorithms(cps) => {
                let vals = resolve_list(cps, grease.sig_alg);
                resolved.push(Resolved {
                    ty: v::EXT_SIGNATURE_ALGORITHMS,
                    body: u16_list_body(&vals)?,
                    pinned: false,
                    emit: true,
                });
            }
            Extension::KeyShare(cps) => {
                let mut entries: Vec<(u16, Vec<u8>)> = Vec::with_capacity(cps.len());
                for cp in cps {
                    let g = cp.resolve(grease.key_share);
                    if v::is_grease(g) {
                        // uTLS：GREASE 的 key_share 条目带一个字节的 {0}。
                        entries.push((g, vec![0u8]));
                    } else {
                        let key = inputs
                            .key_exchange
                            .iter()
                            .find(|(gg, _)| *gg == g)
                            .map(|(_, k)| k.clone())
                            .ok_or(SpecError::MissingKeyExchange(g))?;
                        entries.push((g, key));
                    }
                }
                resolved.push(Resolved {
                    ty: v::EXT_KEY_SHARE,
                    body: key_share_body(&entries)?,
                    pinned: false,
                    emit: true,
                });
            }
            Extension::PreSharedKey(psk) => {
                // 留在列表里（乱序抽取要用它的位置）；**发不发**由 `is_emitted` 决定 ——
                // 没有会话时它零字节，与 uTLS 的 `pskExtLen() == 0` 同义。
                resolved.push(Resolved {
                    ty: v::EXT_PRE_SHARED_KEY,
                    body: psk_body(psk)?,
                    pinned: true,
                    emit: psk.is_emitted(),
                });
            }
            Extension::GreaseEch(opts) => {
                resolved.push(Resolved {
                    ty: v::EXT_ENCRYPTED_CLIENT_HELLO,
                    body: grease_ech_body(&mut stream, opts),
                    pinned: false,
                    emit: true,
                });
            }
            // ── 结构化扩展集（见 `extensions.rs`）──
            Extension::StatusRequest => resolved.push(Resolved {
                ty: v::EXT_STATUS_REQUEST,
                body: vec![v::STATUS_TYPE_OCSP, 0, 0, 0, 0],
                pinned: false,
                emit: true,
            }),
            Extension::ExtendedMasterSecret => resolved.push(Resolved {
                ty: v::EXT_EXTENDED_MASTER_SECRET,
                body: Vec::new(),
                pinned: false,
                emit: true,
            }),
            Extension::RenegotiationInfo(info) => {
                if info.renegotiated_connection.len() > u8::MAX as usize {
                    return Err(SpecError::TooLong {
                        what: "renegotiation_info 的连接串",
                        len: info.renegotiated_connection.len(),
                    });
                }
                let mut body = vec![info.renegotiated_connection.len() as u8];
                body.extend_from_slice(&info.renegotiated_connection);
                resolved.push(Resolved {
                    ty: v::EXT_RENEGOTIATION_INFO,
                    body,
                    pinned: false,
                    emit: true,
                });
            }
            Extension::SessionTicket(t) => resolved.push(Resolved {
                ty: v::EXT_SESSION_TICKET,
                body: t.ticket.clone(),
                pinned: false,
                emit: true,
            }),
            Extension::Cookie(c) => {
                // RFC 8446 §4.2.2：`opaque cookie<1..2^16-1>` ⇒ `u16 长度 + cookie`。
                if c.cookie.len() > u16::MAX as usize {
                    return Err(SpecError::TooLong {
                        what: "cookie",
                        len: c.cookie.len(),
                    });
                }
                let mut body = (c.cookie.len() as u16).to_be_bytes().to_vec();
                body.extend_from_slice(&c.cookie);
                resolved.push(Resolved {
                    ty: v::EXT_COOKIE,
                    body,
                    pinned: false,
                    emit: true,
                });
            }
            Extension::EcPointFormats(p) => {
                if p.formats.len() > u8::MAX as usize {
                    return Err(SpecError::TooLong {
                        what: "ec_point_formats",
                        len: p.formats.len(),
                    });
                }
                let mut body = vec![p.formats.len() as u8];
                body.extend_from_slice(&p.formats);
                resolved.push(Resolved {
                    ty: v::EXT_EC_POINT_FORMATS,
                    body,
                    pinned: false,
                    emit: true,
                });
            }
            Extension::CompressCertificate(c) => {
                resolved.push(Resolved {
                    ty: v::EXT_COMPRESS_CERTIFICATE,
                    body: compress_certificate_body(&c.algorithms)?,
                    pinned: false,
                    emit: true,
                });
            }
            Extension::ApplicationSettings(a) => resolved.push(Resolved {
                ty: v::EXT_APPLICATION_SETTINGS,
                body: extensions::alps_body(&a.protocols),
                pinned: false,
                emit: true,
            }),
            Extension::ApplicationSettingsNew(a) => resolved.push(Resolved {
                ty: v::EXT_APPLICATION_SETTINGS_NEW,
                body: extensions::alps_body(&a.protocols),
                pinned: false,
                emit: true,
            }),
            Extension::SignedCertificateTimestamp => resolved.push(Resolved {
                ty: v::EXT_SCT,
                body: Vec::new(),
                pinned: false,
                emit: true,
            }),
            Extension::PskKeyExchangeModes { modes } => {
                if modes.len() > u8::MAX as usize {
                    return Err(SpecError::TooLong {
                        what: "psk_key_exchange_modes",
                        len: modes.len(),
                    });
                }
                let mut body = vec![modes.len() as u8];
                body.extend_from_slice(modes);
                resolved.push(Resolved {
                    ty: v::EXT_PSK_KEY_EXCHANGE_MODES,
                    body,
                    pinned: false,
                    emit: true,
                });
            }
            Extension::RecordSizeLimit { limit } => resolved.push(Resolved {
                ty: v::EXT_RECORD_SIZE_LIMIT,
                body: limit.to_be_bytes().to_vec(),
                pinned: false,
                emit: true,
            }),
            Extension::SignatureAlgorithmsCert(c) => {
                resolved.push(Resolved {
                    ty: v::EXT_SIGNATURE_ALGORITHMS_CERT,
                    body: extensions::u16_list_body(&c.schemes),
                    pinned: false,
                    emit: true,
                });
            }
            Extension::DelegatedCredentials(d) => {
                resolved.push(Resolved {
                    ty: v::EXT_DELEGATED_CREDENTIALS,
                    body: extensions::u16_list_body(&d.schemes),
                    pinned: false,
                    emit: true,
                });
            }
            Extension::Npn => resolved.push(Resolved {
                ty: v::EXT_NPN,
                body: Vec::new(),
                pinned: false,
                emit: true,
            }),
            Extension::ChannelId { old_codepoint } => resolved.push(Resolved {
                ty: if *old_codepoint {
                    v::EXT_CHANNEL_ID_OLD
                } else {
                    v::EXT_CHANNEL_ID
                },
                body: Vec::new(),
                pinned: false,
                emit: true,
            }),
            Extension::Opaque { id, body } => {
                resolved.push(Resolved {
                    ty: *id,
                    body: body.clone(),
                    pinned: false,
                    emit: true,
                });
            }
        }
    }

    if resolved.is_empty() {
        return Err(SpecError::NoExtensions);
    }
    check_duplicates(&resolved)?;

    // ── 3. 填充 ─────────────────────────────────────────────────────────────
    if let Some((at, policy)) = padding {
        match policy {
            Padding::None => {}
            Padding::Fixed(n) => {
                resolved[at].body = vec![0u8; n as usize];
            }
            Padding::FillTo(target) => {
                // 基准是**整条握手消息**（含 4 字节握手头），此时 padding 体长为 0。
                let base = body_len(spec, &session_id, &resolved)?;
                let target = target as usize;
                if target < base {
                    return Err(SpecError::PaddingTargetUnreachable {
                        target: target as u16,
                    });
                }
                resolved[at].body = vec![0u8; target - base];
            }
            Padding::BoringStyle => {
                // uTLS `u_tls_extensions.go:1115` 的 `BoringPaddingStyle`。
                // 「未填充长」要**扣掉本扩展自己占的 4 字节头**（Go 那边等价于
                // 把 padding 从求和里摘出去后再 Update），否则窗口判定整体偏 4。
                let without = body_len(spec, &session_id, &resolved)? - 4;
                let target = v::PADDING_TARGET_BORING as usize; // 0x200
                if without > v::BORING_PAD_BAND_LOW && without < target {
                    let mut pad = target - without;
                    // Go 原式写作 `paddingLen >= 4+1` —— 那两个数字各有含义，所以写成常量
                    // 而不是字面量：`4` 是 padding 扩展自己的 4 字节头，`1` 是最小填充体。
                    pad = if pad >= PADDING_EXT_HEADER_LEN + MIN_PAD_BODY_LEN {
                        pad - PADDING_EXT_HEADER_LEN
                    } else {
                        MIN_PAD_BODY_LEN
                    };
                    resolved[at].body = vec![0u8; pad];
                } else {
                    // 窗口外 ⇒ **不写字节**，但保留在列表里参与乱序抽取（uTLS 的 `Len()` 返回 0）。
                    resolved[at].emit = false;
                }
            }
        }
    }

    // ── 4. 乱序（在长度确定之后：置换不改变长度）───────────────────────────
    if spec.variability == Variability::Shuffled {
        let n = resolved.len();
        let mut order: Vec<usize> = (0..n).collect();
        let pinned: Vec<bool> = resolved.iter().map(|r| r.pinned).collect();
        stream.shuffle(&mut order, &pinned);
        resolved = order.into_iter().map(|i| resolved[i].clone()).collect();
    }

    // ── 5. 组装 ─────────────────────────────────────────────────────────────
    let mut body: Vec<u8> = Vec::with_capacity(320);
    body.extend_from_slice(&spec.legacy_version.to_be_bytes());
    body.extend_from_slice(&inputs.client_random);

    body.push(session_id.len() as u8);
    body.extend_from_slice(&session_id);

    let ciphers = resolve_list(&spec.cipher_suites, grease.cipher);
    if ciphers.len() * 2 > u16::MAX as usize {
        return Err(SpecError::TooLong {
            what: "密码套件列表",
            len: ciphers.len() * 2,
        });
    }
    body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for c in &ciphers {
        body.extend_from_slice(&c.to_be_bytes());
    }

    body.push(spec.compression_methods.len() as u8);
    body.extend_from_slice(&spec.compression_methods);

    let mut exts: Vec<u8> = Vec::with_capacity(256);
    for r in resolved.iter().filter(|r| r.emit) {
        if r.body.len() > u16::MAX as usize {
            return Err(SpecError::TooLong {
                what: "扩展体",
                len: r.body.len(),
            });
        }
        exts.extend_from_slice(&r.ty.to_be_bytes());
        exts.extend_from_slice(&(r.body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&r.body);
    }
    if exts.len() > u16::MAX as usize {
        return Err(SpecError::TooLong {
            what: "扩展区",
            len: exts.len(),
        });
    }
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    if body.len() > 0x00ff_ffff {
        return Err(SpecError::TooLong {
            what: "握手消息",
            len: body.len(),
        });
    }
    let mut out: Vec<u8> = Vec::with_capacity(4 + body.len());
    out.push(1u8); // handshake type = ClientHello
    out.extend_from_slice(&[
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ]);
    out.extend_from_slice(&body);
    Ok(ClientHello::from_bytes_unchecked(out))
}

// ── 体长（与组装逐字段对应；改一处必须改两处）─────────────────────────────

fn body_len(
    spec: &ClientHelloSpec,
    session_id: &[u8],
    resolved: &[Resolved],
) -> Result<usize, SpecError> {
    // ⚠️ 起手就是 4：padding 的 `FillTo` 目标是**整条握手消息**（含 4 字节握手头），
    // 所以这里的 `n` 必须是 `hello.len()` 而不是 `body.len()`。漏掉这 4 字节的症状是
    // 填充总长恰好差 4 —— 一个不会报错、只会让指纹差一点点的偏差。
    let mut n = 4 + 2 /* legacy_version */ + 32 /* random */ + 1 + session_id.len();
    n += 2 + 2 * spec.cipher_suites.len();
    n += 1 + spec.compression_methods.len();
    n += 2; // 扩展区长度字段
    for r in resolved.iter().filter(|r| r.emit) {
        n += 4 + r.body.len();
    }
    Ok(n)
}

// ── 结构与重复校验 ─────────────────────────────────────────────────────────

fn check_shape(spec: &ClientHelloSpec) -> Result<(), SpecError> {
    if spec.cipher_suites.is_empty() {
        return Err(SpecError::EmptyCipherSuites);
    }
    if spec.compression_methods.is_empty() {
        return Err(SpecError::EmptyCompressionMethods);
    }
    if spec.extensions.is_empty() {
        return Err(SpecError::NoExtensions);
    }
    // RFC 8446 §4.2.11：pre_shared_key 必须是最后一条扩展。uTLS 的每个 `_PSK_` 预设
    // 也都把它列在末尾（`u_parrots.go` 的四个 `_PSK_` case）。这条在**声明层**校验，
    // 而不是等组装时才发现 —— 那时错误已经离原因很远了。
    if let Some(i) = spec
        .extensions
        .iter()
        .position(|e| matches!(e, Extension::PreSharedKey(_)))
        && i + 1 != spec.extensions.len()
    {
        return Err(SpecError::PreSharedKeyNotLast {
            index: i,
            len: spec.extensions.len(),
        });
    }
    Ok(())
}

fn check_duplicates(resolved: &[Resolved]) -> Result<(), SpecError> {
    let mut seen: Vec<u16> = Vec::with_capacity(resolved.len());
    for r in resolved {
        // GREASE 类型本就各不相同，且 uTLS 会在首尾各放一个 —— 不参与重复判定。
        if v::is_grease(r.ty) {
            continue;
        }
        if seen.contains(&r.ty) {
            return Err(SpecError::DuplicateExtension(r.ty));
        }
        seen.push(r.ty);
    }
    Ok(())
}

// ── 各扩展体的编码 ─────────────────────────────────────────────────────────
//
// 除 GREASE-ECH 外全部是标准 TLS 编码。GREASE-ECH 的出处见该函数注释。

fn resolve_list(cps: &[CodePoint], grease: u16) -> Vec<u16> {
    cps.iter().map(|c| c.resolve(grease)).collect()
}

/// `sni_body` 之前的那一步：把调用方给的名字换算成**真正写上线**的名字。
///
/// 逐行对应 uTLS `handshake_client.go:1365` 的 `hostnameInSNI`（也就是 Go 标准库那个函数）：
///
/// ```text
/// host := name
/// if len(host) > 0 && host[0]=='[' && host[len(host)-1]==']' { host = host[1:len(host)-1] }
/// if i := LastIndex(host, "%"); i > 0 { host = host[:i] }      // 去掉 IPv6 zone
/// if ParseIP(host) != nil { return "" }                        // IP 字面量不是合法 SNI
/// for len(name)>0 && name[len(name)-1]=='.' { name = name[:len(name)-1] }  // 去尾点
/// return name
/// ```
///
/// 三处**必须照抄而不是「顺手改好」**的细节：
///
/// 1. 返回值是 `name` 而不是 `host` —— 方括号只对 `ParseIP` 那一步生效，所以
///    `"[example.com]"` 会**带着方括号**被写上线（只有 `"[::1]"` 这类才因命中 IP 而变空）；
/// 2. `%` 的位置判据是 `i > 0`，首字符就是 `%` 时不去 zone；
/// 3. 尾点是**循环**去掉的，`"a.."` 会一路剥到 `"a"`。
///
/// 判据是 uTLS 自带的夹具：`…-Chrome-70-ServerNameIP`（`config.ServerName = "1.1.1.1"`）
/// 的线上扩展列表里没有类型 0 —— 因为这里返回空串。
///
/// 可见性：`pub`。它本来只开到 `hello`（「写字节之前的一步，不是接口」），
/// 但 ECH 的内层也要用它决定「内层带不带 SNI 扩展」（uTLS 的
/// `serverName: hostnameInSNI(config.ServerName)` 同时决定 SNI 与补零分支），
/// 而内层在引擎侧（`utls-engine`）造 —— 同一处语义不能有两份定义。
pub fn hostname_in_sni(name: &str) -> String {
    let mut host = name;
    // Go 的 `len(host) > 0` 只是防 `host[len(host)-1]` 越界的守卫：`starts_with`/`ends_with`
    // 在空串上本来就安全，所以这里不需要那个判断。
    if host.starts_with('[') && host.ends_with(']') {
        host = &host[1..host.len() - 1];
    }
    if let Some(i) = host.rfind('%')
        && i > 0
    {
        host = &host[..i];
    }
    if is_ip_literal(host) {
        return String::new();
    }
    name.trim_end_matches('.').to_string()
}

/// `net.ParseIP(s) != nil` 的等价物。用标准库而不是手写判定：`net.ParseIP` 是个
/// 细节很多的函数（IPv4-mapped、`::` 压缩、八进制前导零在 Go 1.17 被禁），
/// 而 `std::net::IpAddr` 的 `FromStr` 是同一族语义的**权威实现** ——
/// 手写一个「差不多」的判定只会引入一批没人能验证的边界。
fn is_ip_literal(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok()
}

/// `pre_shared_key` 的体（RFC 8446 §4.2.11 / uTLS `readPskIntoBytes`）。
///
/// ```text
/// u16 identities_len
///   per identity: u16 label_len | label | u32 obfuscated_ticket_age
/// u16 binders_len
///   per binder:   u8 binder_len | binder
/// ```
///
/// 两个列表都为空时返回空体（调用方据此不写字节）—— 与 uTLS 的
/// `pskExtLen() == 0 ⇒ Read 返回 (0, io.EOF)` 同义。
fn psk_body(psk: &super::spec::PreSharedKey) -> Result<Vec<u8>, SpecError> {
    if !psk.is_emitted() {
        return Ok(Vec::new());
    }
    if psk.binders.len() != psk.identities.len() {
        return Err(SpecError::BinderCountMismatch {
            identities: psk.identities.len(),
            binders: psk.binders.len(),
        });
    }

    let mut b: Vec<u8> = Vec::new();
    let mut ids: Vec<u8> = Vec::new();
    for id in &psk.identities {
        if id.label.len() > u16::MAX as usize {
            return Err(SpecError::TooLong {
                what: "PSK identity",
                len: id.label.len(),
            });
        }
        ids.extend_from_slice(&(id.label.len() as u16).to_be_bytes());
        ids.extend_from_slice(&id.label);
        ids.extend_from_slice(&id.obfuscated_ticket_age.to_be_bytes());
    }
    if ids.len() > u16::MAX as usize {
        return Err(SpecError::TooLong {
            what: "PSK identities",
            len: ids.len(),
        });
    }
    b.extend_from_slice(&(ids.len() as u16).to_be_bytes());
    b.extend_from_slice(&ids);

    let mut bs: Vec<u8> = Vec::new();
    for binder in &psk.binders {
        if binder.len() > u8::MAX as usize {
            return Err(SpecError::TooLong {
                what: "PSK binder",
                len: binder.len(),
            });
        }
        bs.push(binder.len() as u8);
        bs.extend_from_slice(binder);
    }
    if bs.len() > u16::MAX as usize {
        return Err(SpecError::TooLong {
            what: "PSK binders",
            len: bs.len(),
        });
    }
    b.extend_from_slice(&(bs.len() as u16).to_be_bytes());
    b.extend_from_slice(&bs);
    Ok(b)
}

fn sni_body(host: &str) -> Result<Vec<u8>, SpecError> {
    let h = host.as_bytes();
    if h.len() > u16::MAX as usize {
        return Err(SpecError::ServerNameTooLong(h.len()));
    }
    let mut b = Vec::with_capacity(5 + h.len());
    b.extend_from_slice(&((3 + h.len()) as u16).to_be_bytes());
    b.push(v::SNI_NAME_TYPE_HOST_NAME);
    b.extend_from_slice(&(h.len() as u16).to_be_bytes());
    b.extend_from_slice(h);
    Ok(b)
}

fn alpn_body(protocols: &[Vec<u8>]) -> Result<Vec<u8>, SpecError> {
    let mut inner: Vec<u8> = Vec::new();
    for p in protocols {
        if p.len() > u8::MAX as usize {
            return Err(SpecError::AlpnProtocolTooLong(p.len()));
        }
        inner.push(p.len() as u8);
        inner.extend_from_slice(p);
    }
    if inner.len() > u16::MAX as usize {
        return Err(SpecError::TooLong {
            what: "ALPN 列表",
            len: inner.len(),
        });
    }
    let mut b = Vec::with_capacity(2 + inner.len());
    b.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    b.extend_from_slice(&inner);
    Ok(b)
}

/// `u16 列表长度 + u16 元素` —— `supported_groups` 与 `signature_algorithms` 的形状。
/// `compress_certificate` 的体：`u8 长度(2n) + u16 算法`（与 `extensions::classify` 互逆）。
fn compress_certificate_body(algos: &[u16]) -> Result<Vec<u8>, SpecError> {
    let n = 2 * algos.len();
    if n > u8::MAX as usize {
        return Err(SpecError::TooLong {
            what: "compress_certificate 算法表",
            len: n,
        });
    }
    let mut b = Vec::with_capacity(1 + n);
    b.push(n as u8);
    for a in algos {
        b.extend_from_slice(&a.to_be_bytes());
    }
    Ok(b)
}

fn u16_list_body(vals: &[u16]) -> Result<Vec<u8>, SpecError> {
    let n = vals.len() * 2;
    if n > u16::MAX as usize {
        return Err(SpecError::TooLong {
            what: "u16 列表",
            len: n,
        });
    }
    let mut b = Vec::with_capacity(2 + n);
    b.extend_from_slice(&(n as u16).to_be_bytes());
    for x in vals {
        b.extend_from_slice(&x.to_be_bytes());
    }
    Ok(b)
}

/// `supported_versions`（客户端形态）：**u8** 长度前缀 + u16 版本。
fn supported_versions_body(vals: &[u16]) -> Result<Vec<u8>, SpecError> {
    let n = vals.len() * 2;
    if n > u8::MAX as usize {
        return Err(SpecError::TooLong {
            what: "supported_versions 列表",
            len: n,
        });
    }
    let mut b = Vec::with_capacity(1 + n);
    b.push(n as u8);
    for x in vals {
        b.extend_from_slice(&x.to_be_bytes());
    }
    Ok(b)
}

fn key_share_body(entries: &[(u16, Vec<u8>)]) -> Result<Vec<u8>, SpecError> {
    let mut inner: Vec<u8> = Vec::new();
    for (g, k) in entries {
        if k.len() > u16::MAX as usize {
            return Err(SpecError::TooLong {
                what: "key_share 条目",
                len: k.len(),
            });
        }
        inner.extend_from_slice(&g.to_be_bytes());
        inner.extend_from_slice(&(k.len() as u16).to_be_bytes());
        inner.extend_from_slice(k);
    }
    if inner.len() > u16::MAX as usize {
        return Err(SpecError::TooLong {
            what: "key_share 列表",
            len: inner.len(),
        });
    }
    let mut b = Vec::with_capacity(2 + inner.len());
    b.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    b.extend_from_slice(&inner);
    Ok(b)
}

/// uTLS GREASE ECH 的等价物。
///
/// 线格式照抄 uTLS `u_ech.go` 的 `GREASEEncryptedClientHelloExtension::Read`：
///
/// ```text
/// outer_type(1) | kdf(2) aead(2) | config_id(1) | enc_key_len(2) enc_key | payload_len(2) payload
/// ```
///
/// - 候选套件与候选载荷长度来自 `opts`（**每个预设不同**：Chrome 是 1 套件 + 4 种长度，
///   Firefox 是 2 套件 + 1 种长度）。两个列表都为空时退化成 uTLS 的默认值
///   （AES-128-GCM、载荷 128）—— uTLS 自己也是这么兜的，所以这里照抄而不报错；
/// - 封装密钥长度取自 X25519 的 HPKE 封装密钥 = 32 字节；
/// - 载荷长度 = 候选值 + AEAD tag（uTLS 源码注释里写明了这个 `+16`）。
///
/// **与 uTLS 的唯一差别**：uTLS 会真的做一次 HPKE 封装（用一个哑 X25519 公钥），
/// 这里写的是等长的随机字节。对指纹而言有意义的是**结构与长度分布**，
/// 而 GREASE 的语义正是「服务端必须忽略它」—— 服务端不会去解封装。
/// 这个取舍在 `STATE.md` 的已知缺口里登记。
fn grease_ech_body(stream: &mut Stream, opts: &GreaseEchOptions) -> Vec<u8> {
    // **按线序抽取**：先抽套件（它写在体最前），再 config_id、封装密钥，最后抽载荷长度、
    // 再填载荷。这不是随意的：抽取顺序就是「确定性输出」的一部分，而线序是唯一一个
    // 「读代码就能推出来」的顺序 —— 一旦改成别的顺序，每条与 seed 绑定的事实都会漂，
    // 而漂的方向没人能凭空推断出来。
    let (kdf, aead) = if opts.cipher_suites.is_empty() {
        (v::HPKE_KDF_HKDF_SHA256, v::HPKE_AEAD_AES_128_GCM)
    } else {
        opts.cipher_suites[stream.below(opts.cipher_suites.len() as u32) as usize]
    };

    let mut b: Vec<u8> = Vec::with_capacity(300);
    b.push(v::ECH_OUTER_CLIENT_HELLO);
    b.extend_from_slice(&kdf.to_be_bytes());
    b.extend_from_slice(&aead.to_be_bytes());
    b.push(stream.u8()); // config_id：每连接一个新字节（uTLS 要求不得复用）
    b.extend_from_slice(&(v::X25519_ENCAPSULATED_KEY_LEN as u16).to_be_bytes());
    let mut enc = [0u8; v::X25519_ENCAPSULATED_KEY_LEN];
    stream.fill(&mut enc);
    b.extend_from_slice(&enc);

    let base = if opts.payload_lens.is_empty() {
        128usize
    } else {
        opts.payload_lens[stream.below(opts.payload_lens.len() as u32) as usize] as usize
    };
    let payload_len = base + AEAD_TAG_LEN;
    b.extend_from_slice(&(payload_len as u16).to_be_bytes());
    let start = b.len();
    b.resize(start + payload_len, 0);
    stream.fill(&mut b[start..]);
    b
}

/// uTLS 的 `cipherLen()`：它只认 GREASE ECH 候选表里出现的两种 AEAD，
/// 而 `AES_128_GCM` 与 `ChaCha20Poly1305` 的 tag 都是 16 字节。
const AEAD_TAG_LEN: usize = 16;

/// 一个扩展的线头：`u16 类型 + u16 长度`。
const PADDING_EXT_HEADER_LEN: usize = 4;
/// `BoringPaddingStyle` 在「余量不够减 4」时退化的最小填充体长（Go 里写作字面量 `1`）。
const MIN_PAD_BODY_LEN: usize = 1;
