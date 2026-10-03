//! **OS 熵源 keygen 的 X25519 与 X25519MLKEM768** —— 两把能直接放进 rustls
//! `CryptoProvider::kx_groups` 的 [`SupportedKxGroup`]，以及把 provider 里的这两组
//! 换成它们的助手。
//!
//! # 为什么存在（首条 hello 的一次性成本，2026-10-03 归因）
//!
//! aws-lc 后端的 keygen 走 aws-lc 的 CTR-DRBG。进程内**首次** `RAND_bytes` 要做
//! CPU 特征分派 + 实例化 DRBG（全局 + 每线程），实测 **~35-46 µs**，全落在本
//! provider 的**第一条** hello 上。这笔钱没法从外面绕：aws-lc-rs 的
//! `EphemeralPrivateKey::generate(alg, _rng)` 收下 rng 参数但**忽略**它 —— 熵源焊死
//! 在 aws-lc 的 RAND 里；MLKEM 更没有低层 API（aws-lc-sys 0.45 的绑定里只有
//! EVP/NID，没有 BoringSSL 式的 external-entropy 接口）。ring 后端没有这笔钱
//! （`ring::rand::SystemRandom` 直连内核）；同一个 provider 两个后端，首条 hello
//! 差几十微秒，不是一个该有的形状。
//!
//! 本 crate 把**随机数的来源**换成内核 CSPRNG（`getrandom(2)`），与 ring 后端同一
//! 信任基；**算术分两路**：X25519 仍由 aws-lc 的 C 实现（`X25519_public_from_private`
//! / `X25519`，RFC 7748 含 clamp）；ML-KEM-768 用 [`libcrux_ml_kem`]（Cryspen 的
//! 形式化验证实现，显式随机数 API，simd256）。实现选型是四家同机实测的结论
//! （keygen/encap/decap，µs）：libcrux **24.7/22.3/23.7** · RustCrypto ml-kem
//! 43/39/48 · PQClean C 33.8/32.9 · aws-lc EVP ~30（另付 DRBG）。
//!
//! # 边界（如实）
//!
//! 换的是 X25519 与 X25519MLKEM768（默认组序里的两个）。P-256 / P-384 仍走
//! aws-lc 的 EVP 路径 —— 它们的 keygen 在 aws-lc 的 C 里，首条 hello 对这些组
//! 仍付 DRBG 初始化。ML-KEM keygen 本身 ~25 µs 是真密码学工作（Go 同形状付得
//! 更多），PQ-first 首条 hello 的地板由它决定。
//!
//! # 为什么是独立的小 crate
//!
//! rustls fork 整个 crate `#![forbid(unsafe_code)]` —— unsafe 必须住在 rustls 之外；
//! 而本 crate 又要同时被 `utls-engine`（客户端）与 `reality`（服务端镜像握手）使用，
//! 所以独立成 crate，两边各一行接线（[`with_os_random_keygen`]）。
//!
//! # 判据
//!
//! 本 crate 的 `tests/`：与 x25519-dalek 对拍公钥与共享密钥、低阶对端必须被拒绝、
//! raw 混合组与 stock aws-lc 实现双向互操作（共享密钥逐字节相同）、provider 换源
//! 前后的组名不变。端到端：全部握手判据（本地 + 真栈）经由这条 keygen —— 真栈
//! Xray 的 uTLS 客户端对 libcrux 的 ML-KEM 做解封装，跨实现互操作在 CI 里实测。

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

/// 把 provider `kx_groups` 里的 **X25519 与 X25519MLKEM768** 换成 [`X25519`] /
/// [`X25519_MLKEM768`]（内核熵源 keygen），其余组与顺序原样。重复调用是幂等的。
///
/// 用法（客户端与 REALITY 服务端各一行）：
///
/// ```no_run
/// let provider = x25519_os::with_os_random_keygen(
///     rustls::crypto::aws_lc_rs::default_provider(),
/// );
/// ```
#[must_use]
pub fn with_os_random_keygen(
    mut provider: rustls::crypto::CryptoProvider,
) -> rustls::crypto::CryptoProvider {
    for g in &mut provider.kx_groups {
        match u16::from(g.name()) {
            29 => *g = X25519,
            4588 => *g = X25519_MLKEM768,
            _ => {}
        }
    }
    provider
}

/// ML-KEM-768 与 X25519 的线序长度（rustls `Hybrid` 布局，PQ 在前）：
/// 客户端 share = ek(1184) ‖ x25519_pub(32) = 1216；
/// 服务端 share = ct(1088) ‖ x25519_pub(32) = 1120；
/// 共享密钥 = mlkem(32) ‖ x25519(32) = 64。
const MLKEM768_EK_LEN: usize = 1184;
const MLKEM768_CT_LEN: usize = 1088;
const MLKEM768_DK_LEN: usize = 2400;

/// 内核熵源 keygen 的 **X25519MLKEM768**（混合组）。
///
/// ML-KEM-768 的数学走 [`libcrux_ml_kem`]（Cryspen 的形式化验证实现，simd256 路径，
/// 显式随机数 API：keygen 吃 64 字节 d‖z、encap 吃 32 字节 m —— 内核熵直接进，
/// 不经过 aws-lc 的 DRBG）。X25519 分量就是 [`X25519`] 的那套（内核熵 + aws-lc 算术）。
///
/// # 为什么换掉 aws-lc 的 MLKEM
///
/// aws-lc 的 MLKEM keygen 走 EVP，熵取自其内部 DRBG——首条 hello 要替 DRBG 懒初始化
/// 付 ~55 µs，而 aws-lc-sys 0.45（crates.io 最新）没有为 MLKEM 暴露任何熵注入点
/// （绑定里只有 EVP/NID，没有 BoringSSL 式的 external-entropy API）。速度实测
/// （Ryzen 9 3900X，release）：libcrux keygen 24.7 / encap 22.3 / decap 23.7 µs ——
/// 比现有 EVP 路径还快，比 RustCrypto ml-kem（43/39/48）与 PQClean C（33.8/32.9）
/// 都快。与 aws-lc 实现的互操作由判据双向钉住。
pub static X25519_MLKEM768: &dyn SupportedKxGroup = &OsRandomHybrid;

#[derive(Debug)]
struct OsRandomHybrid;

impl SupportedKxGroup for OsRandomHybrid {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        // 96 字节内核熵：MLKEM 种子（d‖z，64）+ X25519 私钥（32）。
        let mut entropy = Zeroizing::new([0u8; 96]);
        getrandom::fill(entropy.as_mut()).map_err(|_| Error::FailedToGetRandomBytes)?;
        let mut mlkem_seed = [0u8; 64];
        mlkem_seed.copy_from_slice(&entropy[..64]);
        let mut x_priv = Zeroizing::new([0u8; 32]);
        x_priv.copy_from_slice(&entropy[64..]);

        let kp = libcrux_ml_kem::mlkem768::generate_key_pair(mlkem_seed);
        let x_pub = public_from_private(&x_priv);

        let mut combined_pub = Vec::with_capacity(MLKEM768_EK_LEN + X25519_LEN);
        combined_pub.extend_from_slice(kp.public_key().as_ref());
        combined_pub.extend_from_slice(&x_pub);

        Ok(Box::new(OsRandomHybridExchange {
            dk: Zeroizing::new(
                <[u8; MLKEM768_DK_LEN]>::try_from(kp.private_key().as_ref())
                    .expect("MLKEM768 私钥长度固定 2400"),
            ),
            x_priv,
            x_pub,
            combined_pub,
        }))
    }

    fn start_and_complete(
        &self,
        client_share: &[u8],
    ) -> Result<rustls::crypto::CompletedKeyExchange, Error> {
        // 服务端形状：对客户端的 ek 做 encap（m 用内核熵），X25519 起一把新对。
        if client_share.len() != MLKEM768_EK_LEN + X25519_LEN {
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
        }
        let ek = libcrux_ml_kem::mlkem768::MlKem768PublicKey::from(
            <[u8; MLKEM768_EK_LEN]>::try_from(&client_share[..MLKEM768_EK_LEN])
                .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?,
        );
        let client_xpub: &[u8; X25519_LEN] = client_share[MLKEM768_EK_LEN..]
            .try_into()
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;

        let mut m = Zeroizing::new([0u8; 32]);
        getrandom::fill(m.as_mut()).map_err(|_| Error::FailedToGetRandomBytes)?;
        let (ct, shared_m) = libcrux_ml_kem::mlkem768::encapsulate(&ek, *m);

        let x_priv = os_random_private_key()?;
        let x_pub = public_from_private(&x_priv);
        let shared_x = agree(&x_priv, client_xpub)?;

        let mut pub_key = Vec::with_capacity(MLKEM768_CT_LEN + X25519_LEN);
        pub_key.extend_from_slice(ct.as_ref());
        pub_key.extend_from_slice(&x_pub);
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(shared_m.as_ref());
        secret.extend_from_slice(&shared_x);

        Ok(rustls::crypto::CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key,
            secret: SharedSecret::from(secret),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn fips(&self) -> bool {
        // 如实：MLKEM 数学是 aws-lc 同源级别的 FIPS 203 实现（libcrux 形式化验证），
        // 但 X25519 分量不在 FIPS 批准清单内（SP 800-186），且本 crate 无法观测
        // 链接的 aws-lc 是否处于 FIPS 模式 —— 一律 false，不做合规声明。
        false
    }
}

/// 进行中的混合交换：MLKEM 解封装私钥 + X25519 私钥（均 drop 清零）+ 组合公钥。
struct OsRandomHybridExchange {
    dk: Zeroizing<[u8; MLKEM768_DK_LEN]>,
    x_priv: Zeroizing<[u8; 32]>,
    x_pub: [u8; 32],
    combined_pub: Vec<u8>,
}

impl core::fmt::Debug for OsRandomHybridExchange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OsRandomHybridExchange")
            .field("group", &NamedGroup::X25519MLKEM768)
            .field("combined_pub_len", &self.combined_pub.len())
            .finish()
    }
}

impl ActiveKeyExchange for OsRandomHybridExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        // 客户端形状：服务端 share = ct(1088) ‖ x25519_pub(32) = 1120。
        if peer_pub_key.len() != MLKEM768_CT_LEN + X25519_LEN {
            return Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare));
        }
        let ct = libcrux_ml_kem::mlkem768::MlKem768Ciphertext::from(
            <[u8; MLKEM768_CT_LEN]>::try_from(&peer_pub_key[..MLKEM768_CT_LEN])
                .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?,
        );
        let server_xpub: &[u8; 32] = peer_pub_key[MLKEM768_CT_LEN..]
            .try_into()
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let shared_m = libcrux_ml_kem::mlkem768::decapsulate(
            &libcrux_ml_kem::mlkem768::MlKem768PrivateKey::from(*self.dk),
            &ct,
        );
        let shared_x = agree(&self.x_priv, server_xpub)?;
        let mut secret = Vec::with_capacity(64);
        secret.extend_from_slice(shared_m.as_ref());
        secret.extend_from_slice(&shared_x);
        Ok(SharedSecret::from(secret))
    }

    /// 混合组的经典分量可被单独选中（Firefox 148 的 key_share reuse 语义）。
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((NamedGroup::X25519, &self.x_pub))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        let peer: &[u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let shared = agree(&self.x_priv, peer)?;
        Ok(SharedSecret::from(shared.to_vec()))
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn pub_key(&self) -> &[u8] {
        &self.combined_pub
    }
}
