# open-adblock-core

The ad-blocking engine behind [Open AdBlock](https://github.com/ToThangGTVT/open-adblock), as a
standalone, platform-neutral Rust core with stable bindings for Android, desktop JVMs and native
apps on macOS and Windows.

- **Full tunnel**: userspace TCP/UDP stack (smoltcp) behind a TUN device or a host packet queue;
  every outbound socket is protected before use, so traffic never loops back.
- **DNS filtering**: intercepts all port-53 traffic; UDP/TCP, DoH, DoT and DoQ upstreams; TTL
  cache; hosts, domain-suffix, allow and `$important` rules.
- **Network rules**: AdGuard/uBlock network syntax (Brave `adblock-rust`), per-app scoping.
- **Opt-in HTTPS filtering**: per-app and per-domain, leaf certificates minted from a root CA whose
  private key stays in the host's secure store; path rules, cosmetic filters and scriptlets.
- **DPI circumvention**: GoodbyeDPI-style splitting, header tricks and TTL decoys.
- **Privacy**: no payloads or full URLs in logs; only host, app, action and matched rule.

## Layout

```
crates/engine   openadblock-engine  Rust engine; `api` is the only surface bindings use
crates/jni      openadblock-jni     JNI library (libopenadblock_jni) for Android and desktop JVMs
crates/ffi      openadblock-ffi     C ABI (libopenadblock) + include/openadblock.h for Swift, C#, C++
bindings/java                       Java API: AdBlockEngine and its interfaces (no Android deps)
bindings/swift                      Swift package OpenAdBlockCore: the same API as Swift protocols
vendor/                             patched netstack-smoltcp
scripts/                            build-android.sh, test-jvm.sh, test-c.sh, check-jni-exports.py
docs/                               ARCHITECTURE.md, API.md, PLATFORMS.md
```

## Using it

### Android / JVM (Java or Kotlin)

```kotlin
val engine: AdBlockEngine = NativeEngine.get()           // desktop: NativeEngine.load(Path.of(...))
engine.configureDns("""{"protocol":"https","ip":"1.1.1.1","serverName":"cloudflare-dns.com"}""")
engine.replaceRules(dnsLists, browserLists, customRules, true)
engine.setEventListener { json -> queryLog.append(json) }
engine.start(tun.detachFd(), vpnService /* SocketProtector */, systemDns)
```

The Java API is a set of interfaces (`TunnelController`, `FilterController`,
`EngineConfiguration`, `EventController`, `CertificateAuthority`) combined in `AdBlockEngine`, so
app code can depend on the interface and be tested with a fake.

As a Gradle included build (what the Android app does, with this repo as a git submodule):

```kotlin
// settings.gradle.kts
includeBuild("open-adblock-core/bindings/java")
// module build.gradle.kts
implementation("io.github.tothanggtvt.openadblock:openadblock-core")
```

and package the native library with `scripts/build-android.sh app/src/main/jniLibs`.

### Swift (macOS, later iOS)

```bash
scripts/build-apple.sh        # → bindings/swift/Artifacts/COpenAdBlock.xcframework
```

Add `bindings/swift` as a local Swift package and use `NativeEngine.shared` (an `AdBlockEngine`).
A packet tunnel provider calls `startPackets(protector:dns:sink:)` and feeds
`NEPacketTunnelFlow` packets with `send(packet:)`. The macOS app lives in
[open-adblock-mac](https://github.com/ToThangGTVT/open-adblock-mac).

### C#, C++ (Windows, Linux)

Link `libopenadblock` (`cargo build --release -p openadblock-ffi`) and include
`crates/ffi/include/openadblock.h`. Hosts without a TUN file descriptor (macOS
`NEPacketTunnelFlow`, Windows Wintun) use packet mode: `oab_start_packets` + `oab_send_packet`.
See [docs/PLATFORMS.md](docs/PLATFORMS.md) for the status of each platform.

## Building and testing

Rust 1.99.1 (pinned in `rust-toolchain.toml`), Android NDK 28.2.13676358 for Android builds.

```bash
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace -- --test-threads=1
scripts/test-c.sh          # C header + ABI smoke test on the host
scripts/test-jvm.sh        # Java API against the host JNI library (needs JDK 17+)
scripts/build-android.sh out/jniLibs   # four ABIs, verifies every JNI export
scripts/build-apple.sh && (cd bindings/swift && swift test)   # macOS only
```

## Versioning

`VERSION` (crate version) follows semver. `API_VERSION` is the binding contract — function set,
callback signatures and JSON schemas — and is checked at load time by every binding: Java refuses
a native library with another API version; C hosts compare `oab_api_version()` with
`OAB_API_VERSION`. See [docs/API.md](docs/API.md#compatibility).

## License

No license has been chosen for this repository yet; all rights reserved by the author until one
is added. Third-party components keep their own licenses: see
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) and `licenses/`.
