# Changelog

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
