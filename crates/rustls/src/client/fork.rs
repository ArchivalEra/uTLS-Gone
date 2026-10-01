//! FORK(utls-rs): the single seam through which an external ClientHello layer
//! (a `uTLS`-style fingerprint engine) owns this engine's ClientHello.
//!
//! Upstream rustls has no public API for customising the ClientHello, and the
//! maintainers have declined to add one (issues #1421, #1932, #2498; PRs #1564 and
//! #1475 closed unmerged). This module adds exactly the five capabilities that
//! layer needs, and nothing else. All of it is inert unless
//! [`ClientConfig::fork_client_hello`] is set to `Some(..)`.
//!
//! | capability | upstream refusal | patch site |
//! |---|---|---|
//! | (a) use externally supplied ClientHello bytes verbatim | (no API at all) | `client/hs.rs::emit_external_client_hello` |
//! | (b) suppress per-connection extension order shuffling | PR #1730 made it unconditional | `msgs/handshake.rs::ClientExtensions::order_insensitive_extensions_in_random_order` |
//! | (c) advertise cipher suites this engine cannot negotiate | issue #2414 | `client/hs.rs::emit_client_hello_for_retry` |
//! | (d) omit the unconditional TLS 1.2 SCSV | issue #2485 | `client/hs.rs::emit_client_hello_for_retry` |
//! | (e) accept a caller-supplied key share / private key | (no API at all) | `client/hs.rs::ClientHelloInput::start_handshake` |
//!
//! The seam is deliberately **per connection**: capability (e) needs per-connection
//! key material (an ephemeral private key reused across connections is a defect,
//! not a feature), and a `uTLS`-style layer varies GREASE and padding per
//! connection anyway. A plan that is literally fixed is just a [`ClientHelloPlan`]
//! that ignores its `groups` argument; see [`FixedClientHello`].

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use crate::client::ClientConfig;
use crate::crypto::{ActiveKeyExchange, SharedSecret};
use crate::error::Error;
use crate::msgs::enums::NamedGroup;
use crate::sync::Arc;

/// FORK(utls-rs) (e): a key exchange whose ephemeral key material the caller owns.
///
/// The engine offers no way to import a raw private key into one of its own
/// [`ActiveKeyExchange`] implementations, so instead the caller brings the whole
/// exchange. This is what lets a fingerprint layer decide the contents of the
/// `key_share` extension — which group, which public key — instead of accepting the
/// engine's `initial_key_share()`.
///
/// `complete()` takes `&self` rather than consuming the exchange: the engine holds
/// it behind an [`Arc`] and needs the public key available up to the moment the
/// server's share arrives. Zeroizing private key material on drop is the
/// implementation's responsibility.
// FORK(utls-rs): `Debug` 是必需的 —— 这一层的类型要塞进 `ClientConfig`（它 derive 了 Debug）。
pub trait ExternalKeyExchange: Send + Sync + fmt::Debug {
    /// The group, by IANA value. This may be a value this engine's [`NamedGroup`]
    /// enum has no name for.
    fn group(&self) -> u16;

    /// The public key, as it appears in this group's `key_share` entry
    /// (RFC 8446 §4.2.8.1 for FFDHE, §4.2.8.2 for ECDHE).
    fn pub_key(&self) -> Vec<u8>;

    /// Complete the exchange with the server's public key, returning the raw shared
    /// secret. For FFDHE the result must be left-padded with zeros, as required by
    /// RFC 8446 §7.4.1.
    fn complete(&self, peer_pub_key: &[u8]) -> Result<Vec<u8>, Error>;

    /// For a hybrid (PQ) group: the classical component, as `(group, pub_key)`.
    ///
    /// Return `None` for a non-hybrid group (the default).
    fn hybrid_component(&self) -> Option<(u16, Vec<u8>)> {
        None
    }

    /// Complete only the classical component of a hybrid group, given the peer's
    /// public key. Only called if [`Self::hybrid_component`] returned `Some(..)`.
    fn complete_hybrid_component(&self, _peer_pub_key: &[u8]) -> Result<Vec<u8>, Error> {
        Err(Error::General(
            "FORK(utls-rs): hybrid_component() not implemented".into(),
        ))
    }
}

/// FORK(utls-rs): everything the caller may decide about one connection's
/// ClientHello. Produced once per connection by a [`SuppliesClientHello`].
#[derive(Clone, Default)]
pub struct ClientHelloPlan {
    /// FORK(utls-rs) (a): a complete ClientHello *handshake message* —
    /// `HandshakeType::ClientHello` (`0x01`), a three-byte length, then the body.
    ///
    /// When present it is used **verbatim**: those exact bytes go on the wire and
    /// those exact bytes are folded into the handshake transcript. The engine builds
    /// no ClientHello of its own, and the caller is responsible for the bytes being
    /// a well-formed ClientHello consistent with the rest of the configuration —
    /// in particular with [`ClientConfig::versions`] and ALPN, since the engine's
    /// subsequent handshake state is derived from those.
    pub client_hello: Option<Vec<u8>>,

    /// FORK(utls-rs) (a): every extension type present in [`Self::client_hello`],
    /// by IANA value, **including types this engine does not understand** (GREASE,
    /// browser-specific extensions).
    ///
    /// This engine's ClientHello decoder drops unknown extension types, but the
    /// "the server sent an extension we did not offer" check compares against the
    /// full set that was offered, so that set has to come from the side that wrote
    /// the bytes. `None` means "derive it from the decoded ClientHello", which is
    /// correct only when the hello contains no unknown extension types.
    pub sent_extensions: Option<Vec<u16>>,

    /// FORK(utls-rs) (e): the key exchanges backing the `key_share` entries of
    /// [`Self::client_hello`], **one per entry**. A TLS 1.3 handshake cannot be completed
    /// without them (a TLS 1.2 one does not need them).
    ///
    /// It is a list, not one exchange, because a `key_share` extension may carry several
    /// entries (a browser sends one per group it wants to pre-empt a retry for) and the
    /// server may select **any** of them. With a single exchange the handshake could only
    /// complete for the one group the engine happened to be handed; the server picking
    /// another group we had advertised failed with `WrongGroupForKeyShare`. Hand over
    /// every group you put in the bytes, and the engine picks the one the server selects.
    ///
    /// Each exchange's `group()` must match a `key_share` entry in the supplied bytes;
    /// the engine does not cross-check that (it cannot see the bytes' parse result here).
    pub key_exchanges: Vec<Arc<dyn ExternalKeyExchange>>,

    /// FORK(utls-rs) (b): emit extensions in a fixed, reproducible order instead of
    /// shuffling them per connection. Only affects a ClientHello this engine builds
    /// itself.
    pub stable_extension_order: bool,

    /// FORK(utls-rs) (c): cipher suites to advertise on top of the ones this engine
    /// implements, by IANA value. Advertise-only: if the server selects one of
    /// these the handshake fails, because rustls cannot negotiate a suite it does
    /// not implement (upstream issue #2414). Only affects a ClientHello this engine
    /// builds itself.
    pub extra_cipher_suites: Vec<u16>,

    /// FORK(utls-rs) (h): the caller declares that the `0xfe0d` extension in
    /// [`Self::client_hello`] is a **real** ECH offer, not GREASE.
    ///
    /// This is the difference between "a fake ECH extension of the right shape" (which is
    /// all a fingerprint needs) and "this connection is actually trying to hide its
    /// SNI" (which is a protocol behaviour with consequences): with an offer the server
    /// may *accept* it, and acceptance changes which ClientHello the handshake is
    /// authenticated against — the **inner** one, whose transcript and random replace the
    /// outer's for the key schedule (RFC 9849 §6.1.6).
    ///
    /// So the caller has to hand over the inner hello. It built it (it sealed it into the
    /// payload) and this engine cannot recover it — the payload is ciphertext.
    pub ech: Option<EchOffer>,

    /// FORK(utls-rs) (g): the caller put a `pre_shared_key` extension in
    /// [`Self::client_hello`] with a **placeholder** binder, and the engine should
    /// replace that placeholder with the real one.
    ///
    /// This is what makes resumption possible with a caller-built hello. The binder is
    /// `HMAC(finished_key, Hash(Truncate(ClientHello)))` (RFC 8446 §4.2.11.2) and its
    /// inputs are the session secret and the message being hashed — both of which only
    /// exist inside this engine. So the caller says *where* the binder goes and the
    /// engine, which knows the session (see [`PlanRequest::resumption`]), computes it.
    ///
    /// This is a byte patch of a *serialized* message, which capability (a) otherwise
    /// forbids. It is sound for exactly one reason: **only those `binder_len` bytes
    /// change**, so every length field, the transcript hash of the truncated message,
    /// and the handshake state derived from the supplied bytes are all unaffected. A
    /// patch that changed any length would break the transcript and is refused.
    pub psk_binder: Option<PskBinderSlot>,

    /// FORK(utls-rs) (d): do not append `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` when
    /// TLS 1.2 is offered. Upstream appends it unconditionally and declined to make
    /// that optional (issue #2485). Only affects a ClientHello this engine builds
    /// itself.
    pub suppress_renegotiation_scsv: bool,
}

impl fmt::Debug for ClientHelloPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHelloPlan")
            .field(
                "client_hello",
                &self.client_hello.as_ref().map(|bytes| bytes.len()),
            )
            .field("sent_extensions", &self.sent_extensions)
            .field(
                "key_exchanges",
                &self
                    .key_exchanges
                    .iter()
                    .map(|kx| KxGroupDebug(kx.group()))
                    .collect::<Vec<_>>(),
            )
            .field("stable_extension_order", &self.stable_extension_order)
            .field("extra_cipher_suites", &self.extra_cipher_suites)
            .field(
                "suppress_renegotiation_scsv",
                &self.suppress_renegotiation_scsv,
            )
            .finish()
    }
}

/// FORK(utls-rs): what a [`SuppliesClientHello`] is told when the server answers with
/// a `HelloRetryRequest` and the engine needs a *second* ClientHello.
///
/// This is the minimum a fingerprint layer needs to compute its second hello: which
/// group the server asked for, the cookie to echo, and which groups the engine can
/// complete. Everything else the caller already knows — it holds the spec, and it is
/// *required* to reuse the same per-connection inputs (RFC 8446 §4.1.2: only
/// `key_share`, `cookie`, `pre_shared_key` and padding may change), so a second
/// random or a second GREASE draw would be a protocol violation.
#[derive(Clone, Debug, Default)]
pub struct HelloRetryRequestPlan {
    /// The group the server asked for, by IANA value, if its `HelloRetryRequest`
    /// carried a `key_share` extension. `None` means the retry is cookie-only, and
    /// the second hello must keep the same key share.
    pub selected_group: Option<u16>,

    /// The cookie to echo, if the server sent one.
    pub cookie: Option<Vec<u8>>,

    /// The groups the engine can complete for TLS 1.3 — the same list
    /// [`ClientConfig::fork_key_exchange_groups`] returns.
    pub engine_groups: Vec<u16>,

    /// The same session the first ClientHello may have offered, when this connection
    /// is still resuming.
    ///
    /// A retry does **not** invalidate the PSK: RFC 8446 §4.2.11.2 only requires the
    /// binder to be *recomputed* over the new transcript (`message_hash || HRR ||
    /// Truncate(ClientHello2)`), which is why the offer is repeated here rather than
    /// being consumed by the first flight. The engine drops it when the retry's cipher
    /// suite cannot resume from the session's (`UpdateOnHRR` does the same).
    ///
    /// The ticket and age are **unchanged**: the age is relative to when the session
    /// was retrieved, which happened once, before the first flight.
    pub resumption: Option<ResumptionOffer>,
}

/// FORK(utls-rs) (g): where the engine may write the real PSK binder.
///
/// `truncated_len` is the length of `Truncate(ClientHello)` from RFC 8446 §4.2.11.2 —
/// everything up to and including the PSK identities, **excluding the binders vector
/// and its own two-byte length**. The caller computes it (it wrote the bytes) and the
/// engine hashes exactly `client_hello[..truncated_len]`.
///
/// The binder bytes are assumed to sit at the standard place for a single-binder
/// offer: `binders_len(2) || binder_len(1) || binder`. The engine verifies that the
/// byte at `truncated_len + 2` equals `binder_len` before patching, so a caller that
/// gets the layout wrong is told rather than silently corrupted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PskBinderSlot {
    /// Length of `Truncate(ClientHello)` — see the struct docs. The engine hashes
    /// `client_hello[..truncated_len]`.
    pub truncated_len: usize,
    /// How many bytes the binder occupies. Must equal the session suite's hash output
    /// length; the engine checks that before patching.
    pub binder_len: usize,
}

/// FORK(utls-rs) (g): the session this connection may resume with, as **data**.
///
/// Note what is *not* here: the PSK or the binder key. The engine keeps those; the
/// caller gets the two values it must write into the hello (the ticket, which is the
/// PSK identity, and its obfuscated age) plus the binder length it has to reserve.
/// The binder itself comes back through [`ClientHelloPlan::psk_binder`].
#[derive(Clone, Debug)]
pub struct ResumptionOffer {
    /// The ticket to offer as the PSK identity (`PskIdentity.label`).
    pub ticket: Vec<u8>,
    /// `(now - ticket_created) in ms + age_add`, as the server taught us. Written
    /// verbatim into the identity; the engine has already done the arithmetic.
    pub obfuscated_ticket_age: u32,
    /// The binder length to reserve: the hash output length of the session's suite.
    pub binder_len: usize,
}

/// FORK(utls-rs): what the engine tells a [`SuppliesClientHello`] about *this*
/// connection before asking it for a ClientHello.
#[derive(Clone, Debug, Default)]
pub struct PlanRequest {
    /// The groups the engine can complete for TLS 1.3 — see
    /// [`ClientConfig::fork_key_exchange_groups`].
    pub groups: Vec<u16>,

    /// `Some(..)` when this connection has a session to resume with. The caller may
    /// ignore it (an ordinary full handshake) or write a `pre_shared_key` extension
    /// from it and report [`ClientHelloPlan::psk_binder`].
    pub resumption: Option<ResumptionOffer>,
}

/// FORK(utls-rs): the caller's side of the seam.
///
/// Called once per connection, before the first ClientHello is built.
///
/// `groups` is the ordered list of key exchange groups (IANA values) this engine
/// can complete for the enabled protocol versions — which is also exactly the set
/// of groups a `key_share` entry may be supplied for. That is the engine telling
/// the caller which public keys it needs; it is the same list
/// [`ClientConfig::fork_key_exchange_groups`] returns.
// FORK(utls-rs): `Debug` is a supertrait because `ClientConfig` derives `Debug` and
// holds an `Arc<dyn SuppliesClientHello>`. Without this the fork does not compile.
pub trait SuppliesClientHello: Send + Sync + fmt::Debug {
    /// Decide this connection's ClientHello.
    fn plan(&self, request: &PlanRequest) -> Result<ClientHelloPlan, Error>;

    /// FORK(utls-rs): decide the **second** ClientHello, the reply to a
    /// `HelloRetryRequest`.
    ///
    /// The default refuses. That keeps the fork inert for a caller that only ever
    /// supplies one hello ([`FixedClientHello`], and anything written before this
    /// method existed): such a connection fails loudly if a server insists on a
    /// retry, rather than sending a second hello that does not match the first.
    ///
    /// The returned plan's `client_hello` is written verbatim and folded into the
    /// transcript, exactly like the first one. By the time this is called the engine
    /// has already rolled the transcript up (`message_hash || HelloRetryRequest`), so
    /// the returned bytes are just the message — the caller must **not** include the
    /// retry in them, and must reuse the first hello's client random.
    ///
    /// A cookie-only retry arrives with `selected_group: None`: the second hello must
    /// then keep the same `key_share`, and `key_exchange` may be `None` to say so (the
    /// engine keeps using the first hello's exchange).
    fn retry_plan(&self, _retry: &HelloRetryRequestPlan) -> Result<ClientHelloPlan, Error> {
        Err(Error::General(
            "FORK(utls-rs): this SuppliesClientHello does not implement retry_plan(), \
             so an externally supplied ClientHello cannot be used after a HelloRetryRequest"
                .into(),
        ))
    }
}

/// FORK(utls-rs): the degenerate [`SuppliesClientHello`] — the same plan for every
/// connection, which is how "one fixed, byte-stable ClientHello" is expressed.
///
/// A fixed plan means a fixed `key_share` and therefore one ephemeral key reused
/// across connections. That is a deliberate trade-off: byte-stability is the point
/// of a `Stable` preset, and reusing one ECDHE key weakens forward secrecy rather
/// than breaking the handshake. Callers that want per-connection key shares should
/// implement [`SuppliesClientHello`] directly.
#[derive(Debug)]
pub struct FixedClientHello(pub ClientHelloPlan);

impl SuppliesClientHello for FixedClientHello {
    fn plan(&self, _request: &PlanRequest) -> Result<ClientHelloPlan, Error> {
        Ok(self.0.clone())
    }
}

impl ClientConfig {
    /// FORK(utls-rs): the key exchange groups this engine can complete for TLS 1.3,
    /// in the order it would prefer them, as IANA values.
    ///
    /// This is what the engine hands to a [`SuppliesClientHello`], and it is the set
    /// of groups a `key_share` entry may be supplied for.
    pub fn fork_key_exchange_groups(&self) -> Vec<u16> {
        self.provider
            .kx_groups
            .iter()
            .filter(|skxg| skxg.usable_for_version(crate::enums::ProtocolVersion::TLSv1_3))
            .map(|skxg| u16::from(skxg.name()))
            .collect()
    }
}

/// FORK(utls-rs) (e): adapts an [`ExternalKeyExchange`] to the engine's own
/// [`ActiveKeyExchange`].
///
/// Not public: outside the engine this is an implementation detail of the seam.
pub(super) struct ExternalKx {
    inner: Arc<dyn ExternalKeyExchange>,
    pub_key: Vec<u8>,
    hybrid: Option<(NamedGroup, Vec<u8>)>,
}

impl ExternalKx {
    /// Wrap `inner` for use as the engine's key exchange.
    ///
    /// Returns `None` if the caller's public key cannot be represented for the
    /// group it names (see [`NamedGroup`]).
    pub(super) fn boxed(inner: Arc<dyn ExternalKeyExchange>) -> Box<dyn ActiveKeyExchange> {
        let pub_key = inner.pub_key();
        let hybrid = inner
            .hybrid_component()
            .map(|(group, key)| (NamedGroup::from(group), key));
        Box::new(Self {
            inner,
            pub_key,
            hybrid,
        })
    }
}

impl fmt::Debug for ExternalKx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalKx")
            .field("group", &KxGroupDebug(self.inner.group()))
            .finish()
    }
}

impl ActiveKeyExchange for ExternalKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        self.inner
            .complete(peer_pub_key)
            .map(|secret| SharedSecret::from(secret))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::from(self.inner.group())
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        self.hybrid.as_ref().map(|(group, key)| (*group, &key[..]))
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        self.inner
            .complete_hybrid_component(peer_pub_key)
            .map(|secret| SharedSecret::from(secret))
    }
}

/// FORK(utls-rs) (h): a real ECH offer the caller built and sealed.
#[derive(Clone, Debug)]
pub struct EchOffer {
    /// The `ECHConfigList` the offer was built from — the same bytes the caller used to
    /// seal the inner hello. The engine parses it to learn the public name (what the
    /// session is authenticated against if ECH is rejected) and the HPKE suite.
    pub config_list: Vec<u8>,

    /// The **inner** ClientHello: a complete handshake message (`type || u24 len || body`),
    /// byte for byte the plaintext that went into the ECH payload.
    ///
    /// It is needed for two things that only exist on the inside: the inner transcript and
    /// the inner client random. Getting the wrong bytes here does not fail loudly — it
    /// authenticates a handshake nobody else is having — so the engine parses it and
    /// refuses anything that is not a ClientHello.
    pub inner_client_hello: Vec<u8>,
}

/// FORK(utls-rs): a group value printed as its IANA number even when this engine's
/// [`NamedGroup`] enum has no name for it. `NamedGroup` implements `Debug` already,
/// but printing the number keeps the fork's logs honest about unknown groups.
struct KxGroupDebug(u16);

impl fmt::Debug for KxGroupDebug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}
