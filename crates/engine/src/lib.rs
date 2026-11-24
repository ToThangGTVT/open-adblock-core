//! Open AdBlock engine: a platform-neutral, full-tunnel ad-blocking core.
//!
//! The engine owns a userspace TCP/UDP stack behind a TUN device (or a host packet queue), DNS
//! filtering with encrypted upstreams, network/cosmetic rule matching, opt-in HTTPS filtering and
//! DPI circumvention. It has no knowledge of any host OS API: everything platform-specific comes
//! in through a small set of traits ([`sockets::Protector`], [`dns::EventSink`],
//! [`tun::PacketSink`], [`mitm::ca::CaSigner`]).
//!
//! Bindings (JNI, C ABI) and hosts should call only [`api`]. The other modules are public for
//! tests and benchmarks and carry no stability promise.
pub mod api;
pub mod dns;
pub mod dpi;
pub mod filter;
pub mod mitm;
pub mod policy;
pub mod sockets;
pub mod tcp;
pub mod tun;
pub mod udp;

pub use api::{API_VERSION, VERSION};
