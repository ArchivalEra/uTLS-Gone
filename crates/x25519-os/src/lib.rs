//! **OS 熵源 keygen 的 X25519** —— 一把能直接放进 rustls `CryptoProvider::kx_groups`
//! 的 [`SupportedKxGroup`]，以及把 provider 里的 X25519 换成它的一个助手。
//!
//! # 为什么存在（首条 hello 的一次性成本，2026-10-03 归因）
//!
//! aws-lc 后端的 X25519 keygen 走 aws-lc 的 CTR-DRBG。进程内**首次** `RAND_bytes`
//! 要做 CPU 特征分派 + 实例化 DRBG（全局 + 每线程），实测 **~35-46 µs**，全落在本
//! provider 的**第一条** hello 上。这笔钱没法从外面绕：aws-lc-rs 的
//! `EphemeralPrivateKey::generate(alg, _rng)` 收下 rng 参数但**忽略**它 —— 熵源焊死
//! 在 aws-lc 的 RAND 里。ring 后端没有这笔钱（`ring::rand::SystemRandom` 直连内核）；
//! 同一个 provider 两个后端，首条 hello 差 35 µs，不是一个该有的形状。
//!
//! 本 crate 把**随机数的来源**换成内核 CSPRNG（`getrandom(2)`），与 ring 后端同一
//! 信任基；**算术不动**：公钥与共享密钥仍由 aws-lc 的 C 实现
//! （`X25519_public_from_private` / `X25519`，RFC 7748 含 clamp）计算。
//!
//! # 边界（如实）
//!
//! 只换 X25519（默认组序里的第一个经典组）。P-256 / P-384 / MLKEM768 仍走
//! aws-lc 的 EVP 路径 —— 它们需要 aws-lc 的密钥生成，首条 hello 仍付 DRBG 初始化。
//!
//! # 为什么是独立的小 crate
//!
//! rustls fork 整个 crate `#![forbid(unsafe_code)]` —— unsafe 必须住在 rustls 之外；
//! 而本 crate 又要同时被 `utls-engine`（客户端）与 `reality`（服务端镜像握手）使用，
//! 所以独立成 crate，两边各一行接线（[`with_os_random_x25519`]）。
//!
//! # 判据
//!
//! 本 crate 的 `tests/`：与 x25519-dalek 对拍公钥与共享密钥、低阶对端必须被拒绝、
//! provider 换源前后的组名不变。端到端：全部握手判据（本地 + 真栈）经由这条 keygen。

use zeroize::Zeroizing;

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};

// aws-lc 的 C 原语。SAFETY 契约：三个参数各指向 32 字节缓冲区（curve25519.h）。
use aws_lc_sys::{X25519 as c_x25519, X25519_public_from_private as c_x25519_public_from_private};

/// RFC 7748：私钥、公钥与共享密钥都是 32 字节。
pub const X25519_LEN: usize = 32;

/// RFC 7748 §5 的公钥计算：`X25519(scalar, base)`。clamp 由 C 实现在标量乘里做。
///
/// `private_key` 是**未 clamp** 的 32 字节（与 [`X25519`] 的 keygen 产出一致）；
/// 对乘法而言 clamp 与否等价（函数内会 clamp）。
#[must_use]
pub fn public_from_private(private_key: &[u8; X25519_LEN]) -> [u8; X25519_LEN] {
    let mut public_key = [0u8; X25519_LEN];
    // SAFETY: 两个指针各指向 32 字节缓冲区 —— C 函数契约（curve25519.h）。
    unsafe {
        c_x25519_public_from_private(public_key.as_mut_ptr(), private_key.as_ptr());
    }
    public_key
}

/// RFC 7748 §5 的 X25519：与对端公钥做 DH。
///
/// # Errors
/// 对端公钥产生**全零共享密钥**（低阶点，RFC 7748 §6.1 要求中止；
/// RFC 8446 §7.4.1 也要求对低阶点拒绝）⇒ [`Error::PeerMisbehaved`]；
/// C 函数报失败 ⇒ [`Error::PeerMisbehaved`]。
pub fn agree(
    private_key: &[u8; X25519_LEN],
    peer_public_key: &[u8; X25519_LEN],
) -> Result<[u8; X25519_LEN], Error> {
    let mut shared_key = [0u8; X25519_LEN];
    // SAFETY: 三个指针各指向 32 字节缓冲区 —— C 函数契约；返回 1 = 成功。
    let rc = unsafe {
        c_x25519(
            shared_key.as_mut_ptr(),
            private_key.as_ptr(),
            peer_public_key.as_ptr(),
        )
    };
    if rc != 1 {
        return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
    }
    // 低阶点检查必须自己带：底层 `X25519()` 对全零输出**不**拒绝
    // （上游 EVP 路径的同一检查在 aws-lc 内部）。少了它，对端发一把低阶公钥
    // 就能把会话密钥变成已知常数。
    if shared_key.iter().all(|&b| b == 0) {
        return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
    }
    Ok(shared_key)
}

fn os_random_private_key() -> Result<Zeroizing<[u8; X25519_LEN]>, Error> {
    let mut private_key = Zeroizing::new([0u8; X25519_LEN]);
    getrandom::fill(private_key.as_mut()).map_err(|_| Error::FailedToGetRandomBytes)?;
    Ok(private_key)
}

/// 内核 CSPRNG keygen 的 X25519 —— 放进 `CryptoProvider::kx_groups` 即生效。
pub static X25519: &dyn SupportedKxGroup = &OsRandomX25519;

#[derive(Debug)]
struct OsRandomX25519;

impl SupportedKxGroup for OsRandomX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        // 私钥：内核 CSPRNG 的 32 字节（raw —— clamp 在标量乘里做，对乘法等价）。
        let private_key = os_random_private_key()?;
        let public_key = public_from_private(&private_key);
        Ok(Box::new(OsRandomX25519Exchange {
            private_key,
            public_key,
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn fips(&self) -> bool {
        // 与上游一致：X25519 不在 FIPS 批准清单内（SP 800-186 / FIPS 140-3 IG）。
        false
    }
}

/// 进行中的交换：raw 私钥（drop 时清零）+ 预计算公钥。
struct OsRandomX25519Exchange {
    /// 私钥标量。`Zeroizing`：drop 清零 —— 上游 EVP 路径的密钥由 aws-lc 管理，
    /// 这里不持有 C 对象，清零责任在本侧。
    private_key: Zeroizing<[u8; X25519_LEN]>,
    public_key: [u8; X25519_LEN],
}

impl core::fmt::Debug for OsRandomX25519Exchange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // 不打私钥；公钥长度就够了。
        f.debug_struct("OsRandomX25519Exchange")
            .field("group", &NamedGroup::X25519)
            .field("public_key_len", &self.public_key.len())
            .finish()
    }
}

impl ActiveKeyExchange for OsRandomX25519Exchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer: &[u8; X25519_LEN] = peer_pub_key
            .try_into()
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let shared = agree(&self.private_key, peer)?;
        Ok(SharedSecret::from(shared.to_vec()))
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// 把 provider `kx_groups` 里的 **X25519** 换成 [`X25519`]（内核熵源 keygen），
/// 其余组与顺序原样。重复调用是幂等的。
///
/// 用法（客户端与 REALITY 服务端各一行）：
///
/// ```no_run
/// let provider = x25519_os::with_os_random_x25519(
///     rustls::crypto::aws_lc_rs::default_provider(),
/// );
/// ```
#[must_use]
pub fn with_os_random_x25519(
    mut provider: rustls::crypto::CryptoProvider,
) -> rustls::crypto::CryptoProvider {
    for g in &mut provider.kx_groups {
        if u16::from(g.name()) == u16::from(NamedGroup::X25519) {
            *g = X25519;
        }
    }
    provider
}
