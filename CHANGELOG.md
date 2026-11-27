# Changelog

## 0.8.0 — WebSocket relay, memory bounds

- HTTPS filtering relays WebSockets. An HTTP/1.1 `Upgrade: websocket` handshake goes to the
  origin over its own HTTP/1.1 connection and both upgraded streams are copied after the `101`;
  network rules (`$websocket`) apply to the handshake URL. Before, the first socket to each host
  got `501` and the host was bypassed, which broke chat sites such as Zalo Web on first load.
- `proxy::Connector` takes `http1_only` (the ALPN offer for that connection).
- Memory bounds in the tunnel (the macOS extension peaked at ~340 MB):
  - A retransmitted SYN no longer creates a second smoltcp socket that stayed in LISTEN forever;
    handshakes not done within 30 s are dropped; at most 1024 TCP sockets exist (a SYN beyond
    that gets an RST). New `StackBuilder::tcp_max_sockets` / `tcp_control_buffer_size`.
  - The socket↔stream staging rings are 16 KiB instead of the 64 KiB window (the window and
    so throughput are unchanged).
  - The TCP ingress queue is bounded (1024 frames; overflow is dropped, TCP retransmits).
  - WebSocket relays run inside their flow: idle timer, relay slot and network-change abort
    now cover them.
  - UDP flows share one receive buffer per thread instead of 64 KiB each.
  - Decrypted HTTP/2 upstreams use 2 MB / 1 MB flow-control windows instead of 5 MB / 2 MB.
- `oab_set_root_ca` / `oab_generate_root_ca` release the signer context on every early return.

## 0.7.0 — app proxy

- `open_app_proxy` / `openAppProxy` / `oab_open_app_proxy`: a loopback listener (random token)
  through which a host hands over TCP streams it intercepts per app. Streams get the same rules
  and HTTPS decryption as tunnelled TCP; the macOS app uses it to filter browsers only.
- `tcp::relay`: the per-flow logic shared by the tunnel and the app proxy.

## 0.6.1 — Swift binding

- `bindings/swift`: Swift package `OpenAdBlockCore` with the Java API's protocols
  (`AdBlockEngine`, `TunnelController`, …) over the C ABI; `NativeEngine.shared`.
- `scripts/build-apple.sh` builds `COpenAdBlock.xcframework` for macOS.
- CI runs the Swift tests on macOS.

## 0.6.0 — split from the Open AdBlock app

- The Rust engine moves out of `open-adblock/nativecore` into this repository, with its history.
- Workspace: `openadblock-engine` (platform-neutral), `openadblock-jni`, `openadblock-ffi`.
- `api` module: the single surface every binding uses; `API_VERSION` 1.
- Java API (`bindings/java`): `AdBlockEngine` = `TunnelController` + `FilterController` +
  `EngineConfiguration` + `EventController` + `CertificateAuthority`; `NativeEngine` loads
  `libopenadblock_jni` on Android or from a path on desktop JVMs and checks the API version.
- C ABI with `include/openadblock.h` for Swift, C# and C++ hosts.
- Packet mode (`start_packets`/`send_packet`/`PacketSink`) for hosts without a TUN descriptor
  (macOS Network Extension, Windows Wintun).
- Root CA signing generalised: `ExternalSigner` wraps any host key store.
- Scripts: `build-android.sh`, `check-jni-exports.py`, `test-jvm.sh`, `test-c.sh`; CI on Linux,
  macOS and Android NDK.
