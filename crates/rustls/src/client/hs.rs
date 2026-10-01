use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::ops::Deref;

use pki_types::ServerName;

#[cfg(feature = "tls12")]
use super::tls12;
use super::{ResolvesClientCert, Tls12Resumption};
use crate::SupportedCipherSuite;
#[cfg(feature = "logging")]
use crate::bs_debug;
use crate::check::inappropriate_handshake_message;
use crate::client::client_conn::ClientConnectionData;
use crate::client::common::ClientHelloDetails;
use crate::client::ech::{EchConfig, EchState};
// FORK(utls-rs): the externally supplied ClientHello seam.
use crate::client::fork;
use crate::client::{ClientConfig, EchMode, EchStatus, tls13};
use crate::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES as ALL_SUPPORTED_HPKE_SUITES;
use crate::common_state::{CommonState, HandshakeKind, KxState, State};
use crate::msgs::enums::NamedGroup;
use crate::conn::ConnectionRandoms;
use crate::crypto::{ActiveKeyExchange, KeyExchangeAlgorithm};
use crate::enums::{
    AlertDescription, CertificateType, CipherSuite, ContentType, HandshakeType, ProtocolVersion,
};
use crate::error::{Error, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHashBuffer;
use crate::log::{debug, trace};
use crate::msgs::base::Payload;
use crate::msgs::enums::{Compression, ExtensionType};
use crate::msgs::handshake::{
    CertificateStatusRequest, ClientExtensions, ClientExtensionsInput, ClientHelloPayload,
    ClientSessionTicket, ClientTicketRequest, EncryptedClientHello, HandshakeMessagePayload,
    HandshakePayload, HelloRetryRequest, KeyShareEntry, ProtocolName, PskKeyExchangeModes, Random,
    ServerNamePayload, SessionId, SupportedEcPointFormats, SupportedProtocolVersions,
    TransportParameters,
};
use crate::msgs::message::{Message, MessagePayload};
use pki_types::EchConfigListBytes;
use crate::msgs::persist;
use crate::sync::Arc;
use crate::tls13::key_schedule::KeyScheduleEarly;
use crate::tls13::Tls13CipherSuite;
use crate::verify::ServerCertVerifier;

pub(super) type NextState<'a> = Box<dyn State<ClientConnectionData> + 'a>;
pub(super) type NextStateOrError<'a> = Result<NextState<'a>, Error>;
pub(super) type ClientContext<'a> = crate::common_state::Context<'a, ClientConnectionData>;

/// FORK(utls-rs) (e): the key shares offered in one ClientHello.
///
/// Upstream always offers exactly one, so this was `Option<Box<dyn ActiveKeyExchange>>`.
/// A caller-supplied hello may legitimately offer **several** — a browser sends one
/// `key_share` entry per group it wants to pre-empt a HelloRetryRequest for — and then the
/// server is free to select *any* of them. With a single entry the handshake could only
/// complete for the one group the engine happened to hand over; the server picking another
/// group we did advertise failed with `WrongGroupForKeyShare`, which is a defect, not a
/// policy (see `ClientHelloPlan::key_exchanges`).
///
/// `take_for` is where that is fixed: it picks the share whose group the server selected,
/// or — for hybrid groups — the one whose *classical component* matches, which is what
/// upstream's `KeyExchangeChoice` already did for its single share.
pub(super) struct OfferedKeyShares(Vec<Box<dyn ActiveKeyExchange>>);

impl OfferedKeyShares {
    pub(super) fn single(kx: Box<dyn ActiveKeyExchange>) -> Self {
        OfferedKeyShares(vec![kx])
    }

    pub(super) fn new(shares: Vec<Box<dyn ActiveKeyExchange>>) -> Self {
        OfferedKeyShares(shares)
    }

    fn any_group_matches(&self, group: NamedGroup) -> bool {
        self.0.iter().any(|kx| kx.group() == group)
    }

    /// The share the server selected, if we offered it.
    pub(super) fn take_for(&mut self, their: &KeyShareEntry) -> Option<Box<dyn ActiveKeyExchange>> {
        let at = self
            .0
            .iter()
            .position(|kx| kx.group() == their.group || {
                kx.hybrid_component()
                    .is_some_and(|(g, _)| u16::from(g) == u16::from(their.group))
            })?;
        Some(self.0.remove(at))
    }

    /// The single share of an engine-built ClientHello.
    ///
    /// Only reachable from the self-built path: a caller-supplied hello returns from
    /// `emit_external_client_hello` before the extension-building code runs, so the
    /// several-shares case never passes through here.
    fn only(&self) -> &Box<dyn ActiveKeyExchange> {
        self.0
            .first()
            .filter(|_| self.0.len() == 1)
            .expect("FORK(utls-rs): the engine-built path offers exactly one key share")
    }

    fn take_first(self) -> Box<dyn ActiveKeyExchange> {
        self.0
            .into_iter()
            .next()
            .expect("FORK(utls-rs): a ClientHello always offers at least one key share")
    }
}

struct ExpectServerHello {
    input: ClientHelloInput,
    transcript_buffer: HandshakeHashBuffer,
    // The key schedule for sending early data.
    //
    // If the server accepts the PSK used for early data then
    // this is used to compute the rest of the key schedule.
    // Otherwise, it is thrown away.
    //
    // If this is `None` then we do not support early data.
    early_data_key_schedule: Option<KeyScheduleEarly>,
    offered_key_share: Option<OfferedKeyShares>,
    suite: Option<SupportedCipherSuite>,
    ech_state: Option<EchState>,
}

struct ExpectServerHelloOrHelloRetryRequest {
    next: ExpectServerHello,
    extra_exts: ClientExtensionsInput<'static>,
}

pub(super) struct ClientHelloInput {
    pub(super) config: Arc<ClientConfig>,
    pub(super) resuming: Option<persist::Retrieved<ClientSessionValue>>,
    pub(super) random: Random,
    pub(super) sent_tls13_fake_ccs: bool,
    pub(super) hello: ClientHelloDetails,
    pub(super) session_id: SessionId,
    pub(super) server_name: ServerName<'static>,
    pub(super) prev_ech_ext: Option<EncryptedClientHello>,
    /// FORK(utls-rs): this connection's externally supplied ClientHello plan,
    /// resolved once in `new()`. `None` (the default) means the engine builds its own
    /// ClientHello from `config`, exactly as upstream. See `crate::client::fork`.
    pub(super) fork: Option<fork::ClientHelloPlan>,

    /// FORK(utls-rs) (g): the resumption session behind `fork`, when the caller was
    /// offered one. The engine keeps it because the PSK binder needs the session
    /// secret, which never leaves this crate.
    pub(super) fork_resumption: Option<ForkResumption>,
}

/// FORK(utls-rs) (g): a resumable session, split into what the caller may see
/// ([`fork::ResumptionOffer`]) and what only the engine may hold.
pub(super) struct ForkResumption {
    pub(super) offer: fork::ResumptionOffer,
    /// The session secret. Kept **zeroizing** and never handed out: the caller is told
    /// the ticket, the age and the binder length, never this.
    ///
    /// It is kept (rather than a ready-made key schedule) because the schedule is
    /// needed **once per ClientHello** — the binder of a retry is derived over a
    /// different transcript but from the same secret. rustls' own path re-derives it
    /// per flight too (`prepare_resumption` runs again on a retry).
    secret: zeroize::Zeroizing<Vec<u8>>,
    suite: &'static Tls13CipherSuite,
}

impl ForkResumption {
    /// A fresh early key schedule for one ClientHello.
    fn schedule(&self) -> KeyScheduleEarly {
        KeyScheduleEarly::new(self.suite, &self.secret)
    }
}

/// FORK(utls-rs) (g): turn `resuming` into a session the caller may offer.
///
/// Only TLS 1.3 tickets are offered: a TLS 1.2 session-id/ticket resumption is not a
/// PSK and cannot be expressed in a caller-built hello at all (the caller would have
/// to reproduce the whole abbreviated handshake), so it is not offered rather than
/// half-offered.
fn fork_resumption_offer(
    resuming: Option<&persist::Retrieved<ClientSessionValue>>,
) -> Option<ForkResumption> {
    let resuming = resuming?;
    if resuming.ticket().is_empty() {
        return None;
    }
    // `Retrieved::map` is what keeps the retrieval timestamp attached: the obfuscated
    // ticket age is `now - retrieved_at + age_add`, so dropping the wrapper would lose
    // the age entirely (and the server would reject the PSK for a bogus age).
    let tls13 = resuming.map(|v| v.tls13())?;
    Some(ForkResumption {
        offer: fork::ResumptionOffer {
            ticket: tls13.ticket().to_vec(),
            obfuscated_ticket_age: tls13.obfuscated_ticket_age(),
            binder_len: tls13.suite().common.hash_provider.output_len(),
        },
        secret: zeroize::Zeroizing::new(tls13.secret().to_vec()),
        suite: tls13.suite(),
    })
}

impl ClientHelloInput {
    pub(super) fn new(
        server_name: ServerName<'static>,
        extra_exts: &ClientExtensionsInput<'_>,
        cx: &mut ClientContext<'_>,
        config: Arc<ClientConfig>,
    ) -> Result<Self, Error> {
        let mut resuming = ClientSessionValue::retrieve(&server_name, &config, cx);
        let session_id = match &mut resuming {
            Some(_resuming) => {
                debug!("Resuming session");
                match &mut _resuming.value {
                    #[cfg(feature = "tls12")]
                    ClientSessionValue::Tls12(inner) => {
                        // If we have a ticket, we use the sessionid as a signal that
                        // we're  doing an abbreviated handshake.  See section 3.4 in
                        // RFC5077.
                        if !inner.ticket().0.is_empty() {
                            inner.session_id = SessionId::random(config.provider.secure_random)?;
                        }
                        Some(inner.session_id)
                    }
                    _ => None,
                }
            }
            _ => {
                debug!("Not resuming any session");
                None
            }
        };

        // https://tools.ietf.org/html/rfc8446#appendix-D.4
        // https://tools.ietf.org/html/draft-ietf-quic-tls-34#section-8.4
        let session_id = match session_id {
            Some(session_id) => session_id,
            None if cx.common.is_quic() => SessionId::empty(),
            None if !config.supports_version(ProtocolVersion::TLSv1_3, cx.common.protocol) => {
                SessionId::empty()
            }
            None => SessionId::random(config.provider.secure_random)?,
        };

        let hello = ClientHelloDetails::new(
            extra_exts
                .protocols
                .clone()
                .unwrap_or_default(),
            crate::rand::random_u16(config.provider.secure_random)?,
        );

        // ===== FORK(utls-rs) (a)(e)(g): resolve the externally supplied plan =====
        // Once per connection, and only here: capability (e) needs per-connection key
        // material, and a uTLS-style layer varies GREASE/padding per connection too.
        // `config` is moved into `Self` below, so resolve before that.
        let mut fork = None;
        let mut fork_resumption = None;
        if let Some(supplier) = &config.fork_client_hello {
            // Capability (g): the session, as data for the caller plus the key schedule
            // the engine needs to compute the binder from it. Built before the call so
            // the caller can see what it may resume with.
            let offer = fork_resumption_offer(resuming.as_ref());
            fork = Some(supplier.plan(&fork::PlanRequest {
                groups: config.fork_key_exchange_groups(),
                resumption: offer.as_ref().map(|r| r.offer.clone()),
            })?);
            fork_resumption = offer;
        }

        Ok(Self {
            resuming,
            random: Random::new(config.provider.secure_random)?,
            sent_tls13_fake_ccs: false,
            hello,
            session_id,
            server_name,
            prev_ech_ext: None,
            fork,
            fork_resumption,
            config,
        })
    }

    pub(super) fn start_handshake(
        self,
        extra_exts: ClientExtensionsInput<'static>,
        cx: &mut ClientContext<'_>,
    ) -> NextStateOrError<'static> {
        let mut transcript_buffer = HandshakeHashBuffer::new();
        if self
            .config
            .client_auth_cert_resolver
            .has_certs()
        {
            transcript_buffer.set_client_auth_enabled();
        }

        let key_share = if self.config.needs_key_share() {
            // ===== FORK(utls-rs) (e) =====
            // If the caller brought its own key exchange, that is what backs the
            // `key_share` entry (and what completes the handshake) instead of the
            // group this engine would have picked. Note that no `kx_hint` is
            // recorded in `kx_state` in this case: the group may be one this engine
            // has no `SupportedKxGroup` for, so there is nothing to record.
            let supplied = self
                .fork
                .as_ref()
                .map(|plan| plan.key_exchanges.clone())
                .unwrap_or_default();
            match supplied.is_empty() {
                true => Some(OfferedKeyShares::single(tls13::initial_key_share(
                    &self.config,
                    &self.server_name,
                    &mut cx.common.kx_state,
                )?)),
                false => {
                    // FORK(utls-rs): `kx_state` is a state machine, not just a resumption
                    // hint — `KxState::complete()` asserts on it later in the handshake.
                    // Record the first supplied group when this engine knows it, and the
                    // anonymous variant when it does not; `handle_server_hello` then
                    // corrects it to the group the server actually selects (see
                    // `OfferedKeyShares::take_for`).
                    let iana = supplied[0].group();
                    cx.common.kx_state = match self
                        .config
                        .find_kx_group(NamedGroup::from(iana), ProtocolVersion::TLSv1_3)
                    {
                        Some(g) => KxState::Start(g),
                        None => KxState::External,
                    };
                    Some(OfferedKeyShares::new(
                        supplied
                            .into_iter()
                            .map(|kx| fork::ExternalKx::boxed(kx))
                            .collect(),
                    ))
                }
            }
        } else {
            None
        };

        let ech_state = match self.config.ech_mode.as_ref() {
            Some(EchMode::Enable(ech_config)) => {
                Some(ech_config.state(self.server_name.clone(), &self.config)?)
            }
            _ => None,
        };

        emit_client_hello_for_retry(
            transcript_buffer,
            None,
            key_share,
            extra_exts,
            None,
            self,
            cx,
            ech_state,
        )
    }
}

/// Emits the initial ClientHello or a ClientHello in response to
/// a HelloRetryRequest.
///
/// `retryreq` and `suite` are `None` if this is the initial
/// ClientHello.
fn emit_client_hello_for_retry(
    mut transcript_buffer: HandshakeHashBuffer,
    retryreq: Option<&HelloRetryRequest>,
    key_share: Option<OfferedKeyShares>,
    extra_exts: ClientExtensionsInput<'static>,
    suite: Option<SupportedCipherSuite>,
    mut input: ClientHelloInput,
    cx: &mut ClientContext<'_>,
    mut ech_state: Option<EchState>,
) -> NextStateOrError<'static> {
    let config = &input.config;
    // Defense in depth: the ECH state should be None if ECH is disabled based on config
    // builder semantics.
    let forbids_tls12 = cx.common.is_quic() || ech_state.is_some();

    let supported_versions = SupportedProtocolVersions {
        tls12: config.supports_version(ProtocolVersion::TLSv1_2, cx.common.protocol)
            && !forbids_tls12,
        tls13: config.supports_version(ProtocolVersion::TLSv1_3, cx.common.protocol),
    };

    // should be unreachable thanks to config builder
    assert!(supported_versions.any(|_| true));

    // ===== FORK(utls-rs) (a)(b)(c)(d): take this connection's supplied plan =====
    // Everything from here to the end of this function exists to *build* a
    // ClientHello. When the caller supplied one there is nothing to build, so we
    // hand off to `emit_external_client_hello` before doing any of it — in
    // particular before `prepare_resumption` gets to steer extensions that will not
    // be sent. The plan's remaining knobs (b)(c)(d) steer the self-built path below.
    let fork_plan = input.fork.clone().unwrap_or_default();
    if let Some(bytes) = fork_plan.client_hello.clone() {
        return emit_external_client_hello(
            transcript_buffer,
            retryreq,
            key_share,
            bytes,
            fork_plan.sent_extensions.clone(),
            fork_plan.psk_binder,
            fork_plan.ech,
            input,
            cx,
            supported_versions,
        );
    }

    let mut exts = Box::new(ClientExtensions {
        // offer groups which are usable for any offered version
        named_groups: Some(
            config
                .provider
                .kx_groups
                .iter()
                .filter(|skxg| supported_versions.any(|v| skxg.usable_for_version(v)))
                .map(|skxg| skxg.name())
                .collect(),
        ),
        supported_versions: Some(supported_versions),
        signature_schemes: Some(
            config
                .verifier
                .supported_verify_schemes(),
        ),
        extended_master_secret_request: Some(()),
        certificate_status_request: Some(CertificateStatusRequest::build_ocsp()),
        protocols: extra_exts.protocols.clone(),
        ..Default::default()
    });

    if !config
        .crypto_provider()
        .cipher_suites
        .iter()
        .any(|cs| cs.tls13().is_some())
    {
        if let Some(schemes) = &mut exts.signature_schemes {
            schemes.retain(|scheme| scheme.algorithm().is_some());
        }
    }

    match extra_exts.transport_parameters.clone() {
        Some(TransportParameters::Quic(v)) => exts.transport_parameters = Some(v),
        Some(TransportParameters::QuicDraft(v)) => exts.transport_parameters_draft = Some(v),
        None => {}
    };

    if supported_versions.tls13 {
        if let Some(cas_extension) = config.verifier.root_hint_subjects() {
            exts.certificate_authority_names = Some(cas_extension.to_owned());
        }
    }

    // Send the ECPointFormat extension only if we are proposing ECDHE
    if config
        .provider
        .kx_groups
        .iter()
        .any(|skxg| skxg.name().key_exchange_algorithm() == KeyExchangeAlgorithm::ECDHE)
    {
        exts.ec_point_formats = Some(SupportedEcPointFormats::default());
    }

    exts.server_name = match (ech_state.as_ref(), config.enable_sni) {
        // If we have ECH state we have a "cover name" to send in the outer hello
        // as the SNI domain name. This happens unconditionally so we ignore the
        // `enable_sni` value. That will be used later to decide what to do for
        // the protected inner hello's SNI.
        (Some(ech_state), _) => Some(ServerNamePayload::from(&ech_state.outer_name)),

        // If we have no ECH state, and SNI is enabled, try to use the input server_name
        // for the SNI domain name.
        (None, true) => match &input.server_name {
            ServerName::DnsName(dns_name) => Some(ServerNamePayload::from(dns_name)),
            _ => None,
        },

        // If we have no ECH state, and SNI is not enabled, there's nothing to do.
        (None, false) => None,
    };

    if let Some(key_share) = &key_share {
        debug_assert!(supported_versions.tls13);
        let one = key_share.only();
        let mut shares = vec![KeyShareEntry::new(one.group(), one.pub_key())];

        if !retryreq
            .map(|rr| rr.key_share.is_some())
            .unwrap_or_default()
        {
            // Only for the initial client hello, or a HRR that does not specify a kx group,
            // see if we can send a second KeyShare for "free".  We only do this if the same
            // algorithm is also supported separately by our provider for this version
            // (`find_kx_group` looks that up).
            if let Some((component_group, component_share)) =
                one
                    .hybrid_component()
                    .filter(|(group, _)| {
                        config
                            .find_kx_group(*group, ProtocolVersion::TLSv1_3)
                            .is_some()
                    })
            {
                shares.push(KeyShareEntry::new(component_group, component_share));
            }
        }

        exts.key_shares = Some(shares);
    }

    if let Some(cookie) = retryreq.and_then(|hrr| hrr.cookie.as_ref()) {
        exts.cookie = Some(cookie.clone());
    }

    if supported_versions.tls13 {
        // We could support PSK_KE here too. Such connections don't
        // have forward secrecy, and are similar to TLS1.2 resumption.
        exts.preshared_key_modes = Some(PskKeyExchangeModes {
            psk: false,
            psk_dhe: true,
        });

        if let Some(ticket_req) = &config.send_ticket_request {
            exts.ticket_request = Some(ClientTicketRequest {
                new_session_count: ticket_req.new_session_count,
                resumption_count: ticket_req.resumption_count,
            });
        }
    }

    input.hello.offered_cert_compression =
        if supported_versions.tls13 && !config.cert_decompressors.is_empty() {
            exts.certificate_compression_algorithms = Some(
                config
                    .cert_decompressors
                    .iter()
                    .map(|dec| dec.algorithm())
                    .collect(),
            );
            true
        } else {
            false
        };

    if config
        .client_auth_cert_resolver
        .only_raw_public_keys()
    {
        exts.client_certificate_types = Some(vec![CertificateType::RawPublicKey]);
    }

    if config
        .verifier
        .requires_raw_public_keys()
    {
        exts.server_certificate_types = Some(vec![CertificateType::RawPublicKey]);
    }

    // If this is a second client hello we're constructing in response to an HRR, and
    // we've rejected ECH or sent GREASE ECH, then we need to carry forward the
    // exact same ECH extension we used in the first hello.
    if matches!(cx.data.ech_status, EchStatus::Rejected | EchStatus::Grease) & retryreq.is_some() {
        if let Some(prev_ech_ext) = input.prev_ech_ext.take() {
            exts.encrypted_client_hello = Some(prev_ech_ext);
        }
    }

    // Do we have a SessionID or ticket cached for this host?
    let tls13_session = prepare_resumption(&input.resuming, &mut exts, suite, cx, config);

    // Extensions MAY be randomized
    // but they also need to keep the same order as the previous ClientHello
    exts.order_seed = input.hello.extension_order_seed;
    // ===== FORK(utls-rs) (b): a reproducible order instead of the seed-driven shuffle.
    exts.deterministic_order = fork_plan.stable_extension_order;

    let mut cipher_suites: Vec<_> = config
        .provider
        .cipher_suites
        .iter()
        .filter_map(|cs| match cs.usable_for_protocol(cx.common.protocol) {
            true => Some(cs.suite()),
            false => None,
        })
        .collect();

    // ===== FORK(utls-rs) (d) =====
    // Upstream appends this SCSV unconditionally whenever TLS 1.2 is offered, and
    // there is no way to avoid it (issue #2485). It is part of the advertised cipher
    // suite list, so it changes a JA3; the caller may suppress it.
    if supported_versions.tls12 && !fork_plan.suppress_renegotiation_scsv {
        // We don't do renegotiation at all, in fact.
        cipher_suites.push(CipherSuite::TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
    }

    // ===== FORK(utls-rs) (c) =====
    // Upstream can only advertise suites it implements (issue #2414: "unlikely to
    // happen"). A faithful fingerprint sometimes needs exactly that, so the caller
    // may append suite IDs by IANA value. Advertise-only: this engine still cannot
    // *negotiate* them, so a server selecting one fails the handshake rather than
    // silently downgrading. Duplicates of already-advertised suites are dropped,
    // since a duplicate entry would corrupt the advertised list and hence a JA3.
    let fork_extra_suites: Vec<CipherSuite> = fork_plan
        .extra_cipher_suites
        .iter()
        .copied()
        .map(CipherSuite::from)
        .filter(|cs| !cipher_suites.contains(cs))
        .collect();
    cipher_suites.extend(fork_extra_suites);

    let mut chp_payload = ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: input.random,
        session_id: input.session_id,
        cipher_suites,
        compression_methods: vec![Compression::Null],
        extensions: exts,
    };

    let ech_grease_ext = config
        .ech_mode
        .as_ref()
        .and_then(|mode| match mode {
            EchMode::Grease(cfg) => Some(cfg.grease_ext(
                config.provider.secure_random,
                input.server_name.clone(),
                &chp_payload,
            )),
            _ => None,
        });

    match (cx.data.ech_status, &mut ech_state) {
        // If we haven't offered ECH, or have offered ECH but got a non-rejecting HRR, then
        // we need to replace the client hello payload with an ECH client hello payload.
        (EchStatus::NotOffered | EchStatus::Offered, Some(ech_state)) => {
            // Replace the client hello payload with an ECH client hello payload.
            chp_payload = ech_state.ech_hello(chp_payload, retryreq, &tls13_session)?;
            cx.data.ech_status = EchStatus::Offered;
            // Store the ECH extension in case we need to carry it forward in a subsequent hello.
            input.prev_ech_ext = chp_payload
                .encrypted_client_hello
                .clone();
        }
        // If we haven't offered ECH, and have no ECH state, then consider whether to use GREASE
        // ECH.
        (EchStatus::NotOffered, None) => {
            if let Some(grease_ext) = ech_grease_ext {
                // Add the GREASE ECH extension.
                let grease_ext = grease_ext?;
                chp_payload.encrypted_client_hello = Some(grease_ext.clone());
                cx.data.ech_status = EchStatus::Grease;
                // Store the GREASE ECH extension in case we need to carry it forward in a
                // subsequent hello.
                input.prev_ech_ext = Some(grease_ext);
            }
        }
        _ => {}
    }

    // Note what extensions we sent.
    input.hello.sent_extensions = chp_payload.collect_used();
    input.hello.offered_cipher_suites = chp_payload.cipher_suites.clone();

    let mut chp = HandshakeMessagePayload(HandshakePayload::ClientHello(chp_payload));

    let tls13_early_data_key_schedule = match (ech_state.as_mut(), tls13_session) {
        // If we're performing ECH and resuming, then the PSK binder will have been dealt with
        // separately, and we need to take the early_data_key_schedule computed for the inner hello.
        (Some(ech_state), Some(tls13_session)) => ech_state
            .early_data_key_schedule
            .take()
            .map(|schedule| (tls13_session.suite(), schedule)),

        // When we're not doing ECH and resuming, then the PSK binder need to be filled in as
        // normal.
        (_, Some(tls13_session)) => Some((
            tls13_session.suite(),
            tls13::fill_in_psk_binder(&tls13_session, &transcript_buffer, &mut chp),
        )),

        // No early key schedule in other cases.
        _ => None,
    };

    let ch = Message {
        version: match retryreq {
            // <https://datatracker.ietf.org/doc/html/rfc8446#section-5.1>:
            // "This value MUST be set to 0x0303 for all records generated
            //  by a TLS 1.3 implementation ..."
            Some(_) => ProtocolVersion::TLSv1_2,
            // "... other than an initial ClientHello (i.e., one not
            // generated after a HelloRetryRequest), where it MAY also be
            // 0x0301 for compatibility purposes"
            //
            // (retryreq == None means we're in the "initial ClientHello" case)
            None => ProtocolVersion::TLSv1_0,
        },
        payload: MessagePayload::handshake(chp),
    };

    if retryreq.is_some() {
        // send dummy CCS to fool middleboxes prior
        // to second client hello
        tls13::emit_fake_ccs(&mut input.sent_tls13_fake_ccs, cx.common);
    }

    trace!("Sending ClientHello {ch:#?}");

    transcript_buffer.add_message(&ch);
    cx.common.send_msg(ch, false);

    // Calculate the hash of ClientHello and use it to derive EarlyTrafficSecret
    let early_data_key_schedule =
        tls13_early_data_key_schedule.map(|(resuming_suite, schedule)| {
            if !cx.data.early_data.is_enabled() {
                return schedule;
            }

            let (transcript_buffer, random) = match &ech_state {
                // When using ECH the early data key schedule is derived based on the inner
                // hello transcript and random.
                Some(ech_state) => (
                    &ech_state.inner_hello_transcript,
                    &ech_state.inner_hello_random.0,
                ),
                None => (&transcript_buffer, &input.random.0),
            };

            tls13::derive_early_traffic_secret(
                &*config.key_log,
                cx,
                resuming_suite.common.hash_provider,
                &schedule,
                &mut input.sent_tls13_fake_ccs,
                transcript_buffer,
                random,
            );
            schedule
        });

    let next = ExpectServerHello {
        input,
        transcript_buffer,
        early_data_key_schedule,
        offered_key_share: key_share,
        suite,
        ech_state,
    };

    Ok(if supported_versions.tls13 && retryreq.is_none() {
        Box::new(ExpectServerHelloOrHelloRetryRequest {
            next,
            extra_exts: extra_exts.into_owned(),
        })
    } else {
        Box::new(next)
    })
}

/// FORK(utls-rs) (a): emit a ClientHello supplied by the caller, byte for byte.
///
/// The supplied bytes are used twice and never re-encoded: they are what is written
/// to the wire, and they are what is folded into the handshake transcript. That is
/// the whole point of the capability — a byte patch of a *serialized* ClientHello
/// would break the transcript hash and the HelloRetryRequest consistency checks, so
/// the customization has to happen here, at the typed build step, by replacing it
/// wholesale.
///
/// The bytes are parsed once, for bookkeeping only: the state machine consults what
/// we *offered* when the server's reply arrives (chosen cipher suite, ALPN, whether
/// compressed certificates were offered, which extensions we sent). The parsed form
/// is then discarded and the original bytes are sent. Nothing here re-validates the
/// caller's bytes beyond that parse.
#[allow(clippy::too_many_arguments)]
fn emit_external_client_hello(
    mut transcript_buffer: HandshakeHashBuffer,
    retryreq: Option<&HelloRetryRequest>,
    key_share: Option<OfferedKeyShares>,
    mut bytes: Vec<u8>,
    sent_extensions: Option<Vec<u16>>,
    psk_binder: Option<fork::PskBinderSlot>,
    ech: Option<fork::EchOffer>,
    mut input: ClientHelloInput,
    cx: &mut ClientContext<'_>,
    supported_versions: SupportedProtocolVersions,
) -> NextStateOrError<'static> {
    // ===== FORK(utls-rs) (g): fill in the PSK binder =====
    // The caller reserved `slot.binder_len` bytes for it and told us where the
    // truncated message ends; the real value needs the session secret, so it can only
    // be computed here. Same derivation the engine's own path uses
    // (`tls13::fill_in_psk_binder`): hash `Truncate(ClientHello)` with the session
    // suite's hash, then run the early key schedule's binder derivation over it.
    //
    // Only those `binder_len` bytes are written, so every length field, the transcript
    // of the truncated message, and the state the engine derived from the supplied
    // bytes are untouched. That is the one reason this byte patch is sound where
    // capability (a) otherwise forbids patching.
    let mut early_data_key_schedule = None;
    // NOTE: borrowed, not taken — a retry needs the same session again (with a
    // recomputed binder), so it must outlive this flight.
    let fork_resumption = input.fork_resumption.as_ref();
    match (psk_binder, fork_resumption) {
        (Some(slot), Some(resumption)) => {
            if slot.binder_len != resumption.offer.binder_len {
                return Err(Error::General(
                    "FORK(utls-rs): the supplied PSK binder length does not match the session's \
                     hash output length"
                        .into(),
                ));
            }
            let len_byte = bytes.get(slot.truncated_len + 2).copied();
            if len_byte != Some(slot.binder_len as u8) {
                return Err(Error::General(
                    "FORK(utls-rs): the supplied PSK binders layout is not \
                     `binders_len(2) || binder_len(1) || binder` at the reported offset"
                        .into(),
                ));
            }
            let (start, end) = (slot.truncated_len + 3, slot.truncated_len + 3 + slot.binder_len);
            if end > bytes.len() {
                return Err(Error::General(
                    "FORK(utls-rs): the reported PSK binder runs past the end of the ClientHello"
                        .into(),
                ));
            }
            // A fresh schedule per flight; the transcript already contains
            // `message_hash || HelloRetryRequest` when this is the second flight, which
            // is exactly the transcript the binder must cover.
            let hs_hash = transcript_buffer.hash_given(
                resumption.suite.common.hash_provider,
                &bytes[..slot.truncated_len],
            );
            let real = resumption
                .schedule()
                .resumption_psk_binder_key_and_sign_verify_data(&hs_hash);
            if real.as_ref().len() != slot.binder_len {
                return Err(Error::General(
                    "FORK(utls-rs): derived PSK binder has an unexpected length".into(),
                ));
            }
            bytes[start..end].copy_from_slice(real.as_ref());
            early_data_key_schedule = Some(resumption.schedule());
        }
        (Some(_), None) => {
            // The caller reserved room for a binder but this connection has no session
            // to derive it from. A zero binder is *not* a valid one, so going on would
            // silently send a hello the server cannot resume from.
            return Err(Error::General(
                "FORK(utls-rs): the supplied ClientHello declares a PSK binder slot, but this \
                 connection has no session to resume with"
                    .into(),
            ));
        }
        // No PSK offer: an ordinary full handshake, or a hello the caller built with a
        // fake PSK extension of its own.
        (None, _) => {}
    }
    // FORK(utls-rs): a second ClientHello (the reply to a HelloRetryRequest) arrives
    // here too, now that the seam has `SuppliesClientHello::retry_plan`. The caller
    // resolved the retry (new key share, echoed cookie, *reused* client random) and the
    // transcript this function appends to has already been rolled up by
    // `handle_hello_retry_request` — so the bytes are simply the message, and the
    // HRR consistency checks have all run before we got here. `retryreq` stays in the
    // signature because the two cases differ in one visible way: a retry is not an
    // ECH offer, and it must not re-derive `EchStatus`.
    debug_assert!(
        retryreq.is_none() || sent_extensions.is_some(),
        "FORK(utls-rs): a supplied retry ClientHello must also carry its extension list"
    );

    // FORK(utls-rs): the supplied hello may carry an ECH extension, in one of two very
    // different senses:
    //
    // * **GREASE** — a fake of the right shape. `EchStatus` is *not* merely informative
    //   here: the ServerHello path errors with `PeerMisbehaved::UnsolicitedEchExtension`
    //   unless the status records that an ECH extension went out, and a server answering
    //   GREASE ECH with retry configs is the *normal* case. Found by running a real
    //   handshake against tls.browserleaks.com.
    // * **a real offer** (capability (h)) — the caller says so via `plan.ech`, and then
    //   the engine must additionally keep the *inner* hello's transcript and random,
    //   because acceptance switches the handshake onto them.
    // FORK(utls-rs): parse the message we are about to send **once, up front**. Two blocks
    // below read facts out of it — the ECH state, and "learn what we offered" — and one of
    // those facts is the **outer legacy session id**, which only exists on the wire:
    //
    // `EchState::from_supplied` rebuilds the inner hello's transcript with the *outer*
    // session id inside it, because that is what a server does when it reconstructs the
    // inner hello (`decodeInnerClientHello` inserts `outer.sessionId`). Handing it the
    // engine's own `input.session_id` — the value generated in `ClientHelloInput::new`,
    // which is what this function used to do, because the block that learns the caller's
    // value ran *after* the ECH state was built — makes the two sides hash different
    // inner transcripts. The symptom is specific and easy to misread: the server confirms
    // acceptance, the client computes a different confirmation value, judges the offer
    // *rejected*, and the handshake dies with `cannot decrypt peer's message`.
    let payload = MessagePayload::new(ContentType::Handshake, ProtocolVersion::TLSv1_2, &bytes)?;
    let outer_session_id = match &payload {
        MessagePayload::Handshake { parsed, .. } => match &parsed.0 {
            HandshakePayload::ClientHello(chp) => chp.session_id.clone(),
            _ => input.session_id.clone(),
        },
        _ => input.session_id.clone(),
    };

    let mut ech_state = None;
    let ech_ext_present = sent_extensions
        .as_ref()
        .is_some_and(|exts| exts.contains(&u16::from(ExtensionType::EncryptedClientHello)));
    match ech {
        Some(offer) => {
            if !ech_ext_present {
                return Err(Error::General(
                    "FORK(utls-rs): an EchOffer was supplied but the ClientHello has no \
                     encrypted_client_hello extension"
                        .into(),
                ));
            }
            let config = EchConfig::new(
                EchConfigListBytes::from(&offer.config_list[..]),
                ALL_SUPPORTED_HPKE_SUITES,
            )?;
            ech_state = Some(EchState::from_supplied(
                &config,
                &offer.inner_client_hello,
                outer_session_id.as_ref(),
                input.config.provider.secure_random,
                input.config.enable_sni,
            )?);
            cx.data.ech_status = EchStatus::Offered;
        }
        None => {
            if ech_ext_present {
                cx.data.ech_status = EchStatus::Grease;
            }
        }
    }

    // FORK(utls-rs) (a): learn what we offered from the bytes we are about to send,
    // rather than from the config — the two need not agree, and the bytes are the
    // truth about what went on the wire.
    if let MessagePayload::Handshake { parsed, .. } = &payload {
        if let HandshakePayload::ClientHello(chp) = &parsed.0 {
            input.hello.offered_cipher_suites = chp.cipher_suites.clone();
            input.hello.offered_cert_compression =
                chp.certificate_compression_algorithms.is_some();
            // ALPN is checked against what we offered, so it has to come from here.
            input.hello.alpn_protocols = chp.protocols.clone().unwrap_or_default();
            // FORK(utls-rs): the legacy session id, likewise. This engine generates one
            // for itself (RFC 8446 §4.1.2's compatibility measure) and later insists the
            // server echo *that* value — but with a supplied hello the value on the wire
            // is the caller's, so the engine's own is the wrong thing to check against.
            // Found by putting a real HelloRetryRequest through this path: the retry
            // failed with `IllegalHelloRetryRequestWithWrongSessionId`.
            input.session_id = chp.session_id.clone();
            // The decoder above drops extension types it does not know, but this
            // engine rejects a server extension we did not offer — and a fingerprint
            // hello is full of extensions this engine has no name for (GREASE
            // included). So the caller's complete list wins when it supplied one.
            input.hello.sent_extensions = match sent_extensions {
                Some(types) => types.iter().copied().map(ExtensionType::from).collect(),
                None => chp.collect_used(),
            };
        }
    }

    let ch = Message {
        // Same legacy record version an engine-built initial ClientHello uses.
        version: ProtocolVersion::TLSv1_0,
        payload,
    };

    trace!(
        "Sending externally supplied ClientHello ({} bytes, {} cipher suites)",
        bytes.len(),
        input.hello.offered_cipher_suites.len()
    );

    transcript_buffer.add_message(&ch);
    cx.common.send_msg(ch, false);

    let next = ExpectServerHello {
        input,
        transcript_buffer,
        // FORK(utls-rs) (g): when the caller put a PSK for the offered session in the
        // hello, this schedule is what lets the engine accept the server's
        // `pre_shared_key` and derive the resumption keys — i.e. what makes the
        // handshake *resumed* rather than merely PSK-looking.
        early_data_key_schedule,
        offered_key_share: key_share,
        suite: None,
        // FORK(utls-rs) (h): `Some(..)` for a real ECH offer (built from the caller's inner
        // hello), `None` for a GREASE one — acceptance only makes sense for the former.
        ech_state,
    };

    Ok(if supported_versions.tls13 {
        Box::new(ExpectServerHelloOrHelloRetryRequest {
            next,
            // The engine contributes nothing to the extensions of a supplied
            // ClientHello; the empty input is what a retry would have to build from.
            extra_exts: ClientExtensionsInput::default(),
        })
    } else {
        Box::new(next)
    })
}

/// Prepares `exts` and `cx` with TLS 1.2 or TLS 1.3 session
/// resumption.
///
/// - `suite` is `None` if this is the initial ClientHello, or
///   `Some` if we're retrying in response to
///   a HelloRetryRequest.
///
/// This function will push onto `exts` to
///
/// (a) request a new ticket if we don't have one,
/// (b) send our TLS 1.2 ticket after retrieving an 1.2 session,
/// (c) send a request for 1.3 early data if allowed and
/// (d) send a 1.3 preshared key if we have one.
///
/// It returns the TLS 1.3 PSKs, if any, for further processing.
fn prepare_resumption<'a>(
    resuming: &'a Option<persist::Retrieved<ClientSessionValue>>,
    exts: &mut ClientExtensions<'_>,
    suite: Option<SupportedCipherSuite>,
    cx: &mut ClientContext<'_>,
    config: &ClientConfig,
) -> Option<persist::Retrieved<&'a persist::Tls13ClientSessionValue>> {
    // Check whether we're resuming with a non-empty ticket.
    let resuming = match resuming {
        Some(resuming) if !resuming.ticket().is_empty() => resuming,
        _ => {
            if config.supports_version(ProtocolVersion::TLSv1_2, cx.common.protocol)
                && config.resumption.tls12_resumption == Tls12Resumption::SessionIdOrTickets
            {
                // If we don't have a ticket, request one.
                exts.session_ticket = Some(ClientSessionTicket::Request);
            }
            return None;
        }
    };

    let Some(tls13) = resuming.map(|csv| csv.tls13()) else {
        // TLS 1.2; send the ticket if we have support this protocol version
        if config.supports_version(ProtocolVersion::TLSv1_2, cx.common.protocol)
            && config.resumption.tls12_resumption == Tls12Resumption::SessionIdOrTickets
        {
            exts.session_ticket = Some(ClientSessionTicket::Offer(Payload::new(resuming.ticket())));
        }
        return None; // TLS 1.2, so nothing to return here
    };

    if !config.supports_version(ProtocolVersion::TLSv1_3, cx.common.protocol) {
        return None;
    }

    // If the server selected TLS 1.2, we can't resume.
    let suite = match suite {
        Some(SupportedCipherSuite::Tls13(suite)) => Some(suite),
        #[cfg(feature = "tls12")]
        Some(SupportedCipherSuite::Tls12(_)) => return None,
        None => None,
    };

    // If the selected cipher suite can't select from the session's, we can't resume.
    if let Some(suite) = suite {
        suite.can_resume_from(tls13.suite())?;
    }

    tls13::prepare_resumption(config, cx, &tls13, exts, suite.is_some());
    Some(tls13)
}

pub(super) fn process_alpn_protocol(
    common: &mut CommonState,
    offered_protocols: &[ProtocolName],
    selected: Option<&ProtocolName>,
    check_selected_offered: bool,
) -> Result<(), Error> {
    common.alpn_protocol = selected.map(ToOwned::to_owned);

    if let Some(alpn_protocol) = &common.alpn_protocol {
        if check_selected_offered && !offered_protocols.contains(alpn_protocol) {
            return Err(common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::SelectedUnofferedApplicationProtocol,
            ));
        }
    }

    // RFC 9001 says: "While ALPN only specifies that servers use this alert, QUIC clients MUST
    // use error 0x0178 to terminate a connection when ALPN negotiation fails." We judge that
    // the user intended to use ALPN (rather than some out-of-band protocol negotiation
    // mechanism) if and only if any ALPN protocols were configured. This defends against badly-behaved
    // servers which accept a connection that requires an application-layer protocol they do not
    // understand.
    if common.is_quic() && common.alpn_protocol.is_none() && !offered_protocols.is_empty() {
        return Err(common.send_fatal_alert(
            AlertDescription::NoApplicationProtocol,
            Error::NoApplicationProtocol,
        ));
    }

    debug!(
        "ALPN protocol is {:?}",
        common
            .alpn_protocol
            .as_ref()
            .map(|v| bs_debug::BsDebug(v.as_ref()))
    );
    Ok(())
}

pub(super) fn process_server_cert_type_extension(
    common: &mut CommonState,
    config: &ClientConfig,
    server_cert_extension: Option<&CertificateType>,
) -> Result<Option<(ExtensionType, CertificateType)>, Error> {
    process_cert_type_extension(
        common,
        config
            .verifier
            .requires_raw_public_keys(),
        server_cert_extension.copied(),
        ExtensionType::ServerCertificateType,
    )
}

pub(super) fn process_client_cert_type_extension(
    common: &mut CommonState,
    config: &ClientConfig,
    client_cert_extension: Option<&CertificateType>,
) -> Result<Option<(ExtensionType, CertificateType)>, Error> {
    process_cert_type_extension(
        common,
        config
            .client_auth_cert_resolver
            .only_raw_public_keys(),
        client_cert_extension.copied(),
        ExtensionType::ClientCertificateType,
    )
}

impl State<ClientConnectionData> for ExpectServerHello {
    fn handle<'m>(
        mut self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> NextStateOrError<'m>
    where
        Self: 'm,
    {
        let server_hello =
            require_handshake_msg!(m, HandshakeType::ServerHello, HandshakePayload::ServerHello)?;
        trace!("We got ServerHello {server_hello:#?}");

        use crate::ProtocolVersion::{TLSv1_2, TLSv1_3};
        let config = &self.input.config;
        let tls13_supported = config.supports_version(TLSv1_3, cx.common.protocol);

        let server_version = if server_hello.legacy_version == TLSv1_2 {
            server_hello
                .selected_version
                .unwrap_or(server_hello.legacy_version)
        } else {
            server_hello.legacy_version
        };

        let version = match server_version {
            TLSv1_3 if tls13_supported => TLSv1_3,
            TLSv1_2 if config.supports_version(TLSv1_2, cx.common.protocol) => {
                if cx.data.early_data.is_enabled() && cx.common.early_traffic {
                    // The client must fail with a dedicated error code if the server
                    // responds with TLS 1.2 when offering 0-RTT.
                    return Err(PeerMisbehaved::OfferedEarlyDataWithOldProtocolVersion.into());
                }

                if server_hello.selected_version.is_some() {
                    return Err({
                        cx.common.send_fatal_alert(
                            AlertDescription::IllegalParameter,
                            PeerMisbehaved::SelectedTls12UsingTls13VersionExtension,
                        )
                    });
                }

                TLSv1_2
            }
            _ => {
                let reason = match server_version {
                    TLSv1_2 | TLSv1_3 => PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig,
                    _ => PeerIncompatible::ServerDoesNotSupportTls12Or13,
                };
                return Err(cx
                    .common
                    .send_fatal_alert(AlertDescription::ProtocolVersion, reason));
            }
        };

        if server_hello.compression_method != Compression::Null {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SelectedUnofferedCompression,
                )
            });
        }

        let allowed_unsolicited = [ExtensionType::RenegotiationInfo];
        if self
            .input
            .hello
            .server_sent_unsolicited_extensions(server_hello, &allowed_unsolicited)
        {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::UnsupportedExtension,
                PeerMisbehaved::UnsolicitedServerHelloExtension,
            ));
        }

        cx.common.negotiated_version = Some(version);

        // Extract ALPN protocol
        if !cx.common.is_tls13() {
            process_alpn_protocol(
                cx.common,
                &self.input.hello.alpn_protocols,
                server_hello
                    .selected_protocol
                    .as_ref()
                    .map(|s| s.as_ref()),
                self.input.config.check_selected_alpn,
            )?;
        }

        // If ECPointFormats extension is supplied by the server, it must contain
        // Uncompressed.  But it's allowed to be omitted.
        if let Some(point_fmts) = &server_hello.ec_point_formats {
            if !point_fmts.uncompressed {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::HandshakeFailure,
                    PeerMisbehaved::ServerHelloMustOfferUncompressedEcPoints,
                ));
            }
        }

        let Some(Some(suite)) = self
            .input
            .hello
            .offered_cipher_suites
            .contains(&server_hello.cipher_suite)
            .then(|| config.find_cipher_suite(server_hello.cipher_suite, cx.common.protocol))
        else {
            return Err(cx.common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                PeerMisbehaved::SelectedUnofferedCipherSuite,
            ));
        };

        if version != suite.version().version {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::SelectedUnusableCipherSuiteForVersion,
                )
            });
        }

        match self.suite {
            Some(prev_suite) if prev_suite != suite => {
                return Err({
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::SelectedDifferentCipherSuiteAfterRetry,
                    )
                });
            }
            _ => {
                debug!("Using ciphersuite {suite:?}");
                self.suite = Some(suite);
                cx.common.suite = Some(suite);
            }
        }

        // Start our handshake hash, and input the server-hello.
        let mut transcript = self
            .transcript_buffer
            .start_hash(suite.hash_provider());
        transcript.add_message(&m);

        let randoms = ConnectionRandoms::new(self.input.random, server_hello.random);
        // For TLS1.3, start message encryption using
        // handshake_traffic_secret.
        match suite {
            SupportedCipherSuite::Tls13(suite) => {
                tls13::handle_server_hello(
                    cx,
                    server_hello,
                    randoms,
                    suite,
                    transcript,
                    self.early_data_key_schedule,
                    // We always send a key share when TLS 1.3 is enabled.
                    self.offered_key_share
                        .expect("FORK(utls-rs): TLS 1.3 always offers a key share"),
                    &m,
                    self.ech_state,
                    self.input,
                )
            }
            #[cfg(feature = "tls12")]
            SupportedCipherSuite::Tls12(suite) => tls12::CompleteServerHelloHandling {
                randoms,
                transcript,
                input: self.input,
            }
            .handle_server_hello(cx, suite, server_hello, tls13_supported),
        }
    }

    fn into_owned(self: Box<Self>) -> NextState<'static> {
        self
    }
}

impl ExpectServerHelloOrHelloRetryRequest {
    fn into_expect_server_hello(self) -> NextState<'static> {
        Box::new(self.next)
    }

    fn handle_hello_retry_request(
        mut self,
        cx: &mut ClientContext<'_>,
        m: Message<'_>,
    ) -> NextStateOrError<'static> {
        let hrr = require_handshake_msg!(
            m,
            HandshakeType::HelloRetryRequest,
            HandshakePayload::HelloRetryRequest
        )?;
        trace!("Got HRR {hrr:?}");

        cx.common.check_aligned_handshake()?;

        // We always send a key share when TLS 1.3 is enabled.
        let offered_key_share = self
            .next
            .offered_key_share
            .expect("FORK(utls-rs): TLS 1.3 always offers a key share");

        // A retry request is illegal if it contains no cookie and asks for
        // retry of a group we already sent.
        let config = &self.next.input.config;

        // ===== FORK(utls-rs) (a)(e): the second ClientHello =====
        // A supplied ClientHello cannot be *rebuilt* by this engine as the second hello
        // (it would need a new key share, the cookie, and a rolled-up transcript). So
        // the caller supplies that one too, through `retry_plan` — whose default is to
        // refuse. Resolving it here, before the engine's own group lookup below, is
        // deliberate: the group the server asks for may be one this engine has no
        // `SupportedKxGroup` for, while the caller can still complete it.
        //
        // Everything else in this handler still applies to a supplied hello: the
        // session_id echo, the version and cipher-suite checks, the ECH confirmation,
        // and the transcript rollup — the retry bytes are folded in by
        // `emit_external_client_hello` exactly like the first hello's.
        // FORK(utls-rs) (h): a real ECH offer cannot survive a retry on this path.
        // RFC 9849 re-seals for the second hello (and drops `enc`), which needs the HPKE
        // context the *caller* holds — and rustls would need the inner transcript that
        // belongs to that new offer. Rather than proceed with the outer transcript and
        // silently authenticate the wrong handshake, refuse.
        if cx.data.ech_status == EchStatus::Offered
            && self.next.input.fork.as_ref().is_some_and(|p| p.client_hello.is_some())
        {
            return Err(Error::General(
                "FORK(utls-rs): a caller-supplied ClientHello offering ECH cannot be used after \
                 a HelloRetryRequest — the retry needs a re-sealed offer, which the caller must \
                 supply (and this seam does not carry one yet)"
                    .into(),
            ));
        }

        let mut fork_retry: Option<fork::ClientHelloPlan> = None;
        let mut fork_retry_kx: Option<Box<dyn ActiveKeyExchange>> = None;
        let fork_supplied_hello = self
            .next
            .input
            .fork
            .as_ref()
            .is_some_and(|p| p.client_hello.is_some());
        if fork_supplied_hello {
            // The *supplier* is consulted, not the resolved plan: deciding the second
            // hello is a fresh decision with new inputs (the selected group, the cookie).
            let Some(supplier) = config.fork_client_hello.clone() else {
                return Err(Error::General(
                    "FORK(utls-rs): a ClientHello plan was supplied but the config no longer has \
                     a SuppliesClientHello"
                        .into(),
                ));
            };
            // The PSK survives a retry, but only if the suite the server picked can
            // resume from the session's: RFC 8446 §4.2.11.2 requires the binder to be
            // recomputed, and a different hash means a different binder anyway.
            // uTLS's `UpdateOnHRR` drops the PSK in exactly this case
            // ("cipher suite hash mismatch, PSK will not be used").
            // The HRR's own cipher suite is looked up here (the later, authoritative
            // lookup happens after the other validations) purely to compare hashes.
            let hrr_hash = config
                .find_cipher_suite(hrr.cipher_suite, cx.common.protocol)
                .map(|s| s.hash_provider().algorithm());
            let resumption = self
                .next
                .input
                .fork_resumption
                .as_ref()
                .filter(|r| {
                    hrr_hash == Some(r.suite.common.hash_provider.algorithm())
                })
                .map(|r| r.offer.clone());
            let req = fork::HelloRetryRequestPlan {
                selected_group: hrr.key_share.map(u16::from),
                cookie: hrr.cookie.as_ref().map(|c| c.0.to_vec()),
                engine_groups: config.fork_key_exchange_groups(),
                resumption,
            };
            let retry = supplier.retry_plan(&req)?;
            if retry.client_hello.is_none() {
                return Err(Error::General(
                    "FORK(utls-rs): retry_plan() returned a plan with no client_hello — \
                     the second ClientHello must be supplied"
                        .into(),
                ));
            }
            match (req.selected_group, retry.key_exchanges.first().cloned()) {
                (Some(group), Some(kx)) => {
                    if kx.group() != group {
                        return Err(Error::General(alloc::format!(
                            "FORK(utls-rs): retry_plan() brought a key exchange for group \
                             0x{:04x} but the HelloRetryRequest asked for 0x{group:04x}",
                            kx.group()
                        )));
                    }
                    // `kx_state` is a state machine, not merely a hint: it is consulted
                    // when the server's own key share arrives. Record the retry group the
                    // same way the first hello records its own.
                    cx.common.kx_state = match config.find_kx_group(
                        NamedGroup::from(group),
                        ProtocolVersion::TLSv1_3,
                    ) {
                        Some(g) => KxState::Start(g),
                        None => KxState::External,
                    };
                    fork_retry_kx = Some(fork::ExternalKx::boxed(kx));
                }
                (Some(_), None) => {
                    return Err(Error::General(
                        "FORK(utls-rs): the HelloRetryRequest selects a group, so retry_plan() \
                         must bring a key exchange for it"
                            .into(),
                    ));
                }
                // Cookie-only retry: the second hello keeps the key share it already had,
                // and the engine's own `offered_key_share` below carries it forward.
                (None, _) => {}
            }
            fork_retry = Some(retry);
        }

        if let (None, Some(req_group)) = (&hrr.cookie, hrr.key_share) {
            // FORK(utls-rs) (e): with several offered shares the check is "did we already
            // send a share for the requested group" — the hybrid case included.
            if offered_key_share.any_group_matches(req_group) {
                return Err({
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::IllegalHelloRetryRequestWithOfferedGroup,
                    )
                });
            }
        }

        // Or has an empty cookie.
        if let Some(cookie) = &hrr.cookie {
            if cookie.0.is_empty() {
                return Err({
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::IllegalHelloRetryRequestWithEmptyCookie,
                    )
                });
            }
        }

        // Or asks us to change nothing.
        if hrr.cookie.is_none() && hrr.key_share.is_none() {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::IllegalHelloRetryRequestWithNoChanges,
                )
            });
        }

        // Or does not echo the session_id from our ClientHello:
        //
        // > the HelloRetryRequest has the same format as a ServerHello message,
        // > and the legacy_version, legacy_session_id_echo, cipher_suite, and
        // > legacy_compression_method fields have the same meaning
        // <https://www.rfc-editor.org/rfc/rfc8446#section-4.1.4>
        //
        // and
        //
        // > A client which receives a legacy_session_id_echo field that does not
        // > match what it sent in the ClientHello MUST abort the handshake with an
        // > "illegal_parameter" alert.
        // <https://www.rfc-editor.org/rfc/rfc8446#section-4.1.3>
        if hrr.session_id != self.next.input.session_id {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::IllegalHelloRetryRequestWithWrongSessionId,
                )
            });
        }

        // Or asks us to talk a protocol we didn't offer, or doesn't support HRR at all.
        match hrr.supported_versions {
            Some(ProtocolVersion::TLSv1_3) => {
                cx.common.negotiated_version = Some(ProtocolVersion::TLSv1_3);
            }
            _ => {
                return Err({
                    cx.common.send_fatal_alert(
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::IllegalHelloRetryRequestWithUnsupportedVersion,
                    )
                });
            }
        }

        // Or asks us to use a ciphersuite we didn't offer.
        let Some(cs) = config.find_cipher_suite(hrr.cipher_suite, cx.common.protocol) else {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedCipherSuite,
                )
            });
        };

        // Or offers ECH related extensions when we didn't offer ECH.
        if cx.data.ech_status == EchStatus::NotOffered && hrr.encrypted_client_hello.is_some() {
            return Err({
                cx.common.send_fatal_alert(
                    AlertDescription::UnsupportedExtension,
                    PeerMisbehaved::IllegalHelloRetryRequestWithInvalidEch,
                )
            });
        }

        // HRR selects the ciphersuite.
        cx.common.suite = Some(cs);
        cx.common.handshake_kind = Some(HandshakeKind::FullWithHelloRetryRequest);

        // If we offered ECH, we need to confirm that the server accepted it.
        match (self.next.ech_state.as_ref(), cs.tls13()) {
            // If the server did not confirm, then note the new ECH status but
            // continue the handshake. We will abort with an ECH required error
            // at the end.
            (Some(ech_state), Some(tls13_cs))
                if !ech_state.confirm_hrr_acceptance(hrr, tls13_cs, cx.common)? =>
            {
                cx.data.ech_status = EchStatus::Rejected
            }
            (Some(_), None) => {
                unreachable!("ECH state should only be set when TLS 1.3 was negotiated")
            }
            _ => {}
        };

        // This is the draft19 change where the transcript became a tree
        let transcript = self
            .next
            .transcript_buffer
            .start_hash(cs.hash_provider());
        let mut transcript_buffer = transcript.into_hrr_buffer();
        transcript_buffer.add_message(&m);

        // If we offered ECH and the server accepted, we also need to update the separate
        // ECH transcript with the hello retry request message.
        if let Some(ech_state) = self.next.ech_state.as_mut() {
            ech_state.transcript_hrr_update(cs.hash_provider(), &m);
        }

        // Early data is not allowed after HelloRetryrequest
        if cx.data.early_data.is_enabled() {
            cx.data.early_data.rejected();
        }

        // FORK(utls-rs) (e): the caller's retry exchange wins over the engine's own
        // group lookup — it is the one whose public key is in the supplied bytes.
        let key_share = match fork_retry_kx {
            Some(kx) => kx,
            None => match hrr.key_share {
                Some(group) if !offered_key_share.any_group_matches(group) => {
                    let Some(skxg) = config.find_kx_group(group, ProtocolVersion::TLSv1_3) else {
                        return Err(cx.common.send_fatal_alert(
                            AlertDescription::IllegalParameter,
                            PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedNamedGroup,
                        ));
                    };

                    cx.common.kx_state = KxState::Start(skxg);
                    skxg.start()?
                }
                // The server asked for a group we did *not* send a share for: build one.
                // (The engine's own lookup; the caller's retry exchange took precedence above.)
                Some(group) => {
                    let Some(skxg) = config.find_kx_group(group, ProtocolVersion::TLSv1_3) else {
                        return Err(cx.common.send_fatal_alert(
                            AlertDescription::IllegalParameter,
                            PeerMisbehaved::IllegalHelloRetryRequestWithUnofferedNamedGroup,
                        ));
                    };
                    cx.common.kx_state = KxState::Start(skxg);
                    skxg.start()?
                }
                None => offered_key_share.take_first(),
            },
        };

        // FORK(utls-rs) (a): when the caller supplied the second ClientHello too, the
        // early return in `emit_client_hello_for_retry` must use *those* bytes.
        let mut input = self.next.input;
        if let Some(plan) = fork_retry {
            input.fork = Some(plan);
        }

        emit_client_hello_for_retry(
            transcript_buffer,
            Some(hrr),
            Some(OfferedKeyShares::single(key_share)),
            self.extra_exts,
            Some(cs),
            input,
            cx,
            self.next.ech_state,
        )
    }
}

impl State<ClientConnectionData> for ExpectServerHelloOrHelloRetryRequest {
    fn handle<'m>(
        self: Box<Self>,
        cx: &mut ClientContext<'_>,
        m: Message<'m>,
    ) -> NextStateOrError<'m>
    where
        Self: 'm,
    {
        match m.payload {
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::ServerHello(..)),
                ..
            } => self
                .into_expect_server_hello()
                .handle(cx, m),
            MessagePayload::Handshake {
                parsed: HandshakeMessagePayload(HandshakePayload::HelloRetryRequest(..)),
                ..
            } => self.handle_hello_retry_request(cx, m),
            payload => Err(inappropriate_handshake_message(
                &payload,
                &[ContentType::Handshake],
                &[HandshakeType::ServerHello, HandshakeType::HelloRetryRequest],
            )),
        }
    }

    fn into_owned(self: Box<Self>) -> NextState<'static> {
        self
    }
}

fn process_cert_type_extension(
    common: &mut CommonState,
    client_expects: bool,
    server_negotiated: Option<CertificateType>,
    extension_type: ExtensionType,
) -> Result<Option<(ExtensionType, CertificateType)>, Error> {
    match (client_expects, server_negotiated) {
        (true, Some(CertificateType::RawPublicKey)) => {
            Ok(Some((extension_type, CertificateType::RawPublicKey)))
        }
        (true, _) => Err(common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            Error::PeerIncompatible(PeerIncompatible::IncorrectCertificateTypeExtension),
        )),
        (_, Some(CertificateType::RawPublicKey)) => {
            unreachable!("Caught by `PeerMisbehaved::UnsolicitedEncryptedExtension`")
        }
        (_, _) => Ok(None),
    }
}

pub(super) enum ClientSessionValue {
    Tls13(persist::Tls13ClientSessionValue),
    #[cfg(feature = "tls12")]
    Tls12(persist::Tls12ClientSessionValue),
}

impl ClientSessionValue {
    fn retrieve(
        server_name: &ServerName<'static>,
        config: &ClientConfig,
        cx: &mut ClientContext<'_>,
    ) -> Option<persist::Retrieved<Self>> {
        let found = config
            .resumption
            .store
            .take_tls13_ticket(server_name)
            .map(ClientSessionValue::Tls13)
            .or_else(|| {
                #[cfg(feature = "tls12")]
                {
                    config
                        .resumption
                        .store
                        .tls12_session(server_name)
                        .map(ClientSessionValue::Tls12)
                }

                #[cfg(not(feature = "tls12"))]
                None
            })
            .and_then(|resuming| {
                resuming.compatible_config(&config.verifier, &config.client_auth_cert_resolver)
            })
            .and_then(|resuming| {
                let now = config
                    .current_time()
                    .map_err(|_err| debug!("Could not get current time: {_err}"))
                    .ok()?;

                let retrieved = persist::Retrieved::new(resuming, now);
                match retrieved.has_expired() {
                    false => Some(retrieved),
                    true => None,
                }
            })
            .or_else(|| {
                debug!("No cached session for {server_name:?}");
                None
            });

        if let Some(resuming) = &found {
            if cx.common.is_quic() {
                cx.common.quic.params = resuming
                    .tls13()
                    .map(|v| v.quic_params());
            }
        }

        found
    }

    fn common(&self) -> &persist::ClientSessionCommon {
        match self {
            Self::Tls13(inner) => &inner.common,
            #[cfg(feature = "tls12")]
            Self::Tls12(inner) => &inner.common,
        }
    }

    fn tls13(&self) -> Option<&persist::Tls13ClientSessionValue> {
        match self {
            Self::Tls13(v) => Some(v),
            #[cfg(feature = "tls12")]
            Self::Tls12(_) => None,
        }
    }

    fn compatible_config(
        self,
        server_cert_verifier: &Arc<dyn ServerCertVerifier>,
        client_creds: &Arc<dyn ResolvesClientCert>,
    ) -> Option<Self> {
        match &self {
            Self::Tls13(v) => v
                .compatible_config(server_cert_verifier, client_creds)
                .then_some(self),
            #[cfg(feature = "tls12")]
            Self::Tls12(v) => v
                .compatible_config(server_cert_verifier, client_creds)
                .then_some(self),
        }
    }
}

impl Deref for ClientSessionValue {
    type Target = persist::ClientSessionCommon;

    fn deref(&self) -> &Self::Target {
        self.common()
    }
}
