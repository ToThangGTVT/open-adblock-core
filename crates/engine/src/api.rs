//! The stable, binding-friendly surface of the engine.
//!
//! Every binding (JNI for Android/JVM, C ABI for Swift/C#/C++) is a thin translation of these
//! functions, so behaviour is identical on every host. Configuration crosses as JSON strings to
//! keep the ABI small and forward compatible: unknown fields are ignored, missing fields keep
//! their defaults. See `docs/API.md` for the schemas.
//!
//! There is one engine per process. Configuration calls are valid before `start` and while
//! running; they take effect for new flows immediately.
use crate::{
    dns, filter, mitm, policy,
    sockets::Protector,
    tun::{Engine, NetworkConfig, PacketSink, TunnelIo},
};
use rcgen::{PublicKeyData, SignatureAlgorithm, SigningKey, PKCS_ECDSA_P256_SHA256};
use std::{
    fmt, io,
    net::IpAddr,
    sync::{atomic::Ordering, Arc, Mutex},
};
use tokio::sync::mpsc;

pub use crate::dns::EventSink;
pub use crate::mitm::ca::CaSigner;
pub use crate::sockets::Protector as SocketProtector;
pub use crate::tun::PacketSink as TunnelPacketSink;

/// Engine release, `MAJOR.MINOR.PATCH`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Version of the binding contract: function set, callback signatures and JSON schemas.
///
/// Additive changes keep the number; anything a host could break on bumps it. Hosts compare it
/// with the value they were written against instead of parsing [`VERSION`].
pub const API_VERSION: u32 = 1;

/// Names of the values returned by [`counters`], in order.
pub const COUNTER_NAMES: [&str; 8] = [
    "packets_in",
    "packets_out",
    "tcp_opened",
    "udp_opened",
    "protect_denied",
    "tcp_up",
    "tcp_down",
    "network_resets",
];

/// Packets a host may queue toward the engine before [`send_packet`] reports back-pressure.
pub const PACKET_QUEUE: usize = 1024;

struct Running {
    engine: Engine,
    inbound: Option<mpsc::Sender<Vec<u8>>>,
}
static ENGINE: Mutex<Option<Running>> = Mutex::new(None);

fn engine() -> std::sync::MutexGuard<'static, Option<Running>> {
    ENGINE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug)]
pub enum StartError {
    /// `stop` must be called first.
    AlreadyRunning,
    Io(io::Error),
}
impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning => f.write_str("engine already running"),
            Self::Io(error) => write!(f, "engine failed to start: {error}"),
        }
    }
}
impl std::error::Error for StartError {}

/// Parses the upstream DNS address the virtual resolver forwards to. Accepts an IPv4/IPv6
/// literal; an IPv6 zone suffix (`fe80::1%wlan0`) is dropped. Anything else means "none".
pub fn parse_dns(text: &str) -> Option<IpAddr> {
    text.split('%').next().unwrap_or("").trim().parse().ok()
}

fn network(dns: Option<&str>) -> NetworkConfig {
    NetworkConfig {
        dns: dns.and_then(parse_dns),
        probe_ipv6: true,
        ..NetworkConfig::default()
    }
}

fn start_io(
    io: TunnelIo,
    inbound: Option<mpsc::Sender<Vec<u8>>>,
    protector: Arc<dyn Protector>,
    dns: Option<&str>,
) -> Result<(), StartError> {
    let mut slot = engine();
    if slot.is_some() {
        return Err(StartError::AlreadyRunning);
    }
    let engine = Engine::start_io(io, protector, network(dns)).map_err(StartError::Io)?;
    *slot = Some(Running { engine, inbound });
    Ok(())
}

/// Starts the tunnel on a TUN descriptor. The engine takes ownership of `fd` and closes it on
/// every path, including failure.
#[cfg(unix)]
pub fn start_fd(
    fd: std::os::fd::OwnedFd,
    protector: Arc<dyn Protector>,
    dns: Option<&str>,
) -> Result<(), StartError> {
    start_io(TunnelIo::Fd(fd), None, protector, dns)
}

/// Starts the tunnel with host-driven packet I/O: the host feeds app packets with
/// [`send_packet`] and receives the engine's packets through `outbound`.
pub fn start_packets(
    protector: Arc<dyn Protector>,
    dns: Option<&str>,
    outbound: Arc<dyn PacketSink>,
) -> Result<(), StartError> {
    let (sender, inbound) = mpsc::channel(PACKET_QUEUE);
    start_io(
        TunnelIo::Packets { inbound, outbound },
        Some(sender),
        protector,
        dns,
    )
}

/// Queues one IP packet from the host toward the engine (packet mode only). Returns false when
/// the engine is not running in packet mode or the queue is full; the packet is then dropped,
/// which TCP/QUIC recover from like any lost packet.
pub fn send_packet(packet: &[u8]) -> bool {
    engine()
        .as_ref()
        .and_then(|running| running.inbound.as_ref())
        .is_some_and(|inbound| inbound.try_send(packet.to_vec()).is_ok())
}

/// Stops the tunnel and joins its thread. Pending metadata is flushed to the event sink. Safe to
/// call when not running.
pub fn stop() {
    let running = engine().take();
    if let Some(mut running) = running {
        running.inbound = None;
        running.engine.shutdown();
    }
}

/// Tells the engine the physical network changed: open upstream sockets are dropped and new
/// flows use `dns`. Blocks until both relay loops applied the change (normally < 2 s).
pub fn update_network(dns: Option<&str>) -> bool {
    engine()
        .as_ref()
        .is_some_and(|running| running.engine.update_network(network(dns)))
}

/// True while the tunnel thread is alive. It turns false on its own if packet I/O fails.
pub fn is_running() -> bool {
    engine()
        .as_ref()
        .is_some_and(|running| running.engine.running.load(Ordering::Acquire))
}

/// Traffic counters since `start`, named by [`COUNTER_NAMES`]. Zero when stopped.
pub fn counters() -> [i64; 8] {
    engine()
        .as_ref()
        .map(|running| running.engine.stats.snapshot())
        .unwrap_or([0; 8])
}

/// App/firewall/IPv6/DPI policy. Returns false and keeps the previous policy on invalid JSON.
pub fn configure_policy(json: &str) -> bool {
    policy::configure(json)
}

/// DNS upstreams, block mode, cache and logging options. False keeps the previous options.
pub fn configure_dns(json: &str) -> bool {
    dns::configure(json)
}

/// HTTPS filtering scope (apps, domains). False keeps the previous scope.
pub fn configure_https(json: &str) -> bool {
    mitm::configure(json)
}

/// Compiles filter lists. `dns` lists feed only the domain matcher, `browser` lists only
/// decrypted HTTPS; `custom` is the user's own rules and feeds both. With `apply` false the
/// lists are only validated. Returns `{"loaded":n,"ignored":n,"errors":[{"line":n,"message":".."}]}`.
pub fn replace_rules(dns: &str, browser: &str, custom: &str, apply: bool) -> String {
    let report = if apply {
        filter::replace_lists(dns, browser, custom)
    } else {
        filter::Rules::compile_lists(dns, browser, custom).report
    };
    serde_json::to_string(&report).unwrap_or_else(|_| "{}".into())
}

/// Installs AdGuard Scriptlets `scriptlets.corelibs.json` / `redirects.json` (either may be
/// empty). Returns `{"scriptlets":n,"redirects":n,"skipped":n}` or `{"error":"..."}`; on error
/// the previous set stays active.
pub fn set_resources(scriptlets: &str, redirects: &str) -> String {
    let value = match filter::resources::install(scriptlets, redirects) {
        Ok(loaded) => serde_json::to_value(&loaded).unwrap_or_default(),
        Err(error) => serde_json::json!({ "error": error }),
    };
    value.to_string()
}

/// Receives batched query-log/statistics JSON. `None` detaches the current sink.
pub fn set_event_sink(sink: Option<Arc<dyn EventSink>>) {
    dns::set_sink(sink);
}

/// Delivers pending events to the sink now instead of at the next 5 s batch.
pub fn flush_events() {
    dns::flush();
}

/// Records request previews (method, path, query and a truncated body) of one app for `minutes`,
/// tagged with `session`, so the user can inspect what that app sends. Only the app the user
/// picked is captured; `minutes <= 0` ends capture.
pub fn set_request_capture(app: i32, session: i64, minutes: i32) {
    dns::set_request_capture(app, session, minutes);
}

/// Longest TBS certificate the engine asks a host signer to sign.
pub const MAX_SIGN_INPUT: usize = 8192;

/// A root CA key held by the host (Android Keystore, macOS Keychain, Windows CNG). The engine
/// never sees the private key: it sends TBS bytes and receives a DER ECDSA-P256-SHA256
/// signature.
pub struct ExternalSigner {
    public_point: Vec<u8>,
    sign: Box<SignFn>,
}
/// Returns a DER signature of the input, or `None` to refuse.
pub type SignFn = dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync;
impl ExternalSigner {
    /// `public_point` is the uncompressed P-256 point (65 bytes, leading 0x04).
    pub fn shared(
        public_point: Vec<u8>,
        sign: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
    ) -> Option<Arc<dyn CaSigner>> {
        if public_point.len() != 65 || public_point[0] != 4 {
            return None;
        }
        Some(Arc::new(Self {
            public_point,
            sign: Box::new(sign),
        }))
    }
}
impl PublicKeyData for ExternalSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.public_point
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}
impl SigningKey for ExternalSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        if data.len() > MAX_SIGN_INPUT {
            return Err(rcgen::Error::RemoteKeyError);
        }
        (self.sign)(data)
            .filter(|signature| !signature.is_empty() && signature.len() <= 128)
            .ok_or(rcgen::Error::RemoteKeyError)
    }
}

/// Creates a new self-signed root CA certificate (DER) for the host-held key.
pub fn generate_ca(signer: Arc<dyn CaSigner>) -> Option<Vec<u8>> {
    mitm::ca::generate(signer).ok()
}

/// Installs the root CA used to mint leaf certificates, or removes it with `None` (HTTPS
/// filtering then stays off). False when the certificate does not match the signer.
pub fn set_ca(authority: Option<(Arc<dyn CaSigner>, Vec<u8>)>) -> bool {
    match authority {
        None => mitm::ca::set(None, vec![]),
        Some((signer, der)) => mitm::ca::set(Some(signer), der),
    }
}
