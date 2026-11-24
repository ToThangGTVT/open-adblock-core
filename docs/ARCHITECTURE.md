# Architecture

```
 host app (Kotlin/Java)        host app (Swift)          host app (C#/C++)
        │                             │                          │
 bindings/java  (interfaces)          │                          │
        │ JNI                         │ C ABI                    │ C ABI
 crates/jni ─────────────┐   crates/ffi + openadblock.h ─────────┘
                         ▼            ▼
                 crates/engine :: api   (the only binding-facing surface)
                         │
   tun ── tcp/udp relays ── dns ── filter ── mitm (HTTPS) ── dpi ── policy ── sockets
                         │
              host traits: Protector · EventSink · PacketSink · CaSigner
```

## Rules for the layers

1. **The engine knows no host API.** No JNI, no Objective-C, no Win32 in `crates/engine`.
   Everything the host provides crosses one of four traits:
   - `sockets::Protector` — exclude an outbound socket from the tunnel; identify a flow's app.
   - `dns::EventSink` — receive batched query-log/statistics JSON.
   - `tun::PacketSink` — receive packets toward apps when the host owns packet I/O.
   - `mitm::ca::CaSigner` — sign with the root CA key the host keeps (`api::ExternalSigner`).
2. **Bindings only translate.** `crates/jni` and `crates/ffi` convert types and call `api::*`.
   Validation, defaults and lifecycle live in `api`, so every host behaves the same. A new binding
   (e.g. UniFFI for Kotlin Multiplatform, a .NET package) is another thin crate over `api`.
3. **Configuration is JSON.** Adding a field never changes a function signature, and unknown
   fields are ignored, so an old host keeps working with a newer engine.
4. **One engine per process**, owned by `api`. Configuration (`configure_*`, rules, CA) is global
   and valid before and during a run.

## Invariants to keep

- Every outbound socket is created through `sockets` and protected before connect/bind/send. A
  failed or missing protector closes the socket (fail closed).
- Never log or report payloads, bodies or full URLs, except request capture the user explicitly
  starts for one app (`set_request_capture`).
- HTTPS filtering is off unless a root CA is installed **and** `configure_https` enables apps;
  banking/payment/health domains are always excluded (`mitm::sensitive`). Upstream TLS always
  verifies WebPKI and hostname; there is no insecure verifier.
- The root CA private key never enters the engine; only TBS bytes and signatures cross.
- Pinned dependency versions (`=x.y.z`); review the license before adding one and record it in
  `THIRD_PARTY_LICENSES.md`.

## Packet I/O

`tun::TunnelIo` has two forms:

| Form | Hosts | Flow |
| --- | --- | --- |
| `Fd(OwnedFd)` | Android `VpnService`, Linux TUN, macOS utun | engine reads/writes the descriptor |
| `Packets { inbound, outbound }` | macOS `NEPacketTunnelFlow`, Windows Wintun | host calls `send_packet`; engine calls `PacketSink::packet` |

Both feed the same stack, relays and filters.

## Threads

`api::start_*` spawns one tunnel thread with a current-thread Tokio runtime. Host callbacks are
invoked on that thread (and on DNS/HTTPS worker tasks running on it), so they must be quick and
thread-safe. `stop` joins the thread and flushes pending events.
