# Changelog

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
