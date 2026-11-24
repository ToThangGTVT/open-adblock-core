# open-adblock-core — notes for agents

Read docs/ARCHITECTURE.md (layer rules, invariants) and docs/API.md before changing code.

- `crates/engine` must not depend on any host API. Bindings (`crates/jni`, `crates/ffi`) only
  translate and call `openadblock_engine::api`.
- Changing a binding-visible function, callback or JSON meaning: update Rust `api`, Java
  (`bindings/java`), C (`crates/ffi`, `include/openadblock.h`), Swift (`bindings/swift`) and
  docs/API.md together, and bump
  `API_VERSION` (Rust, `AdBlockEngine.API_VERSION`, `OAB_API_VERSION`) if a host could break.
- `NativeBindings.java` and `crates/jni/src/lib.rs` must match; `scripts/check-jni-exports.py`
  enforces it. Keep `META-INF/proguard/openadblock-core.pro` in sync with callback interfaces.
- Before pushing: cargo fmt/clippy/test (see README), `scripts/test-c.sh`, `scripts/test-jvm.sh`.
- Consumer: the Open AdBlock Android app pins this repo as a git submodule.
