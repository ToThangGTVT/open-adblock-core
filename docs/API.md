# API reference

The same operations exist in several forms. Rust `openadblock_engine::api` is the source of truth;
Java (`bindings/java`), C (`crates/ffi/include/openadblock.h`) and Swift (`bindings/swift`, the
same protocols as Java over the C ABI) mirror it one to one.

| Operation | Java (`AdBlockEngine`) | C | Rust `api::` |
| --- | --- | --- | --- |
| Engine release | `version()` | `oab_version` | `VERSION` |
| Binding contract | `apiVersion()` | `oab_api_version` | `API_VERSION` |
| Start on TUN fd | `start(fd, protector, dns)` | `oab_start_fd` | `start_fd` |
| Start, host packets | `startPackets(protector, dns, sink)` | `oab_start_packets` | `start_packets` |
| Feed one packet | `sendPacket(bytes)` | `oab_send_packet` | `send_packet` |
| Stop | `stop()` | `oab_stop` | `stop` |
| Network changed | `updateNetwork(dns)` | `oab_update_network` | `update_network` |
| Running? | `isRunning()` | `oab_is_running` | `is_running` |
| Counters | `counters()` | `oab_counters` | `counters` |
| Policy | `configurePolicy(json)` | `oab_configure_policy` | `configure_policy` |
| DNS | `configureDns(json)` | `oab_configure_dns` | `configure_dns` |
| HTTPS scope | `configureHttps(json)` | `oab_configure_https` | `configure_https` |
| Filter lists | `replaceRules(dns, browser, custom, apply)` | `oab_replace_rules` | `replace_rules` |
| Scriptlets | `setResources(scriptlets, redirects)` | `oab_set_resources` | `set_resources` |
| Events | `setEventListener(l)` / `flushEvents()` | `oab_set_event_listener` / `oab_flush_events` | `set_event_sink` / `flush_events` |
| Request capture | `setRequestCapture(app, session, min)` | `oab_set_request_capture` | `set_request_capture` |
| Root CA | `generateRootCa`, `setRootCa`, `clearRootCa` | `oab_generate_root_ca`, `oab_set_root_ca` | `generate_ca`, `set_ca` |

`dns` arguments are an IP literal for the plain resolver the virtual DNS address forwards to
(an IPv6 `%zone` suffix is ignored); empty/`null` means none.

## Callbacks

| Java | C | Called when |
| --- | --- | --- |
| `SocketProtector.protect(fd)` | `OabSocketProtector.protect` | before every outbound socket is used; `false` closes it |
| `SocketProtector.connectionOwner(...)` | `.connection_owner` | new tunnelled flow; return app id or -1 |
| `EngineEventListener.onEvents(json)` | `OabEventListener.on_events` | every 5 s, on a full batch, on stop |
| `PacketSink.onPacket(bytes)` | `OabPacketSink.on_packet` | packet mode: one packet toward apps |
| `CertificateSigner.sign(data)` | `OabCertificateSigner.sign` | minting the root or a leaf certificate |

App ids are whatever the host's `connectionOwner` returns: Android UIDs, Windows PIDs, etc. The
same ids are used in the policy JSON below.

## JSON schemas

Each `configure*` call replaces its whole section. Fields are camelCase; missing fields take the
default shown; unknown fields are ignored. Invalid JSON returns `false` and keeps the old value.

### Policy — `configurePolicy`

```json
{
  "blockQuic": true,          // drop QUIC (UDP 443) for HTTPS-filtered apps so they fall back to TCP
  "ipv6": true,               // false drops IPv6 from apps
  "bypassUids": [],           // app ids routed around filtering
  "blockedUids": [],          // app ids with no network at all (firewall); wins over bypass
  "packages": {"10123": ["com.example.app"]},   // app id → package/bundle names for HTTPS scope
  "dpi": {
    "enabled": false, "httpSplit": 2, "httpsSplit": 2, "splitAtHost": true,
    "hostReplace": true, "hostRemoveSpace": true, "hostMixCase": false, "methodSpace": false,
    "keepAlive": true, "disorder": false, "fake": false, "fakeTtl": 5, "blockQuic": true,
    "blacklist": [], "allowNoSni": false
  }
}
```

### DNS — `configureDns`

```json
{
  "protocol": "system",       // system | udp | tcp | tls (DoT) | https (DoH) | quic (DoQ)
  "ip": "",                   // upstream IP literal; required unless protocol is "system"
  "serverName": "",           // TLS name; required for tls/https/quic
  "path": "/dns-query",       // DoH path
  "port": 0,                  // 0 = protocol default (53, 853, 443)
  "blockMode": "zero",        // zero (0.0.0.0/::) | nxdomain
  "logging": true             // false keeps only aggregate counts in events
}
```

### HTTPS — `configureHttps`

```json
{ "enabled": false, "apps": ["com.android.chrome"] }
```

Decryption also requires an installed root CA (`setRootCa`).

### Rule report — `replaceRules`

```json
{ "loaded": 1234, "ignored": 5, "errors": [ { "line": 7, "message": "..." } ] }
```

### Events — `EngineEventListener`

```json
{
  "events": [
    { "timestamp": 1764000000000, "domain": "ads.example", "blocked": true,
      "matchedRule": "||ads.example^", "cached": false, "uid": 10123, "protocol": "dns",
      "requestPreview": { "session": 1, "method": "GET", "path": "/", "query": null,
                          "body": null, "urlTruncated": false, "bodyTruncated": false } }
  ],
  "totals": [ { "timestamp": 1764000000000, "total": 10, "blocked": 3 } ]
}
```

`requestPreview` appears only during a request capture. `totals` are per-minute buckets.

### Counters

Index order (Java `TrafficCounters`, C `OAB_COUNTER_*`): packets in, packets out, TCP opened, UDP
opened, protect denied, TCP bytes up, TCP bytes down, network resets.

## Compatibility

- `API_VERSION` changes when a host could break: a removed/renamed function, a changed callback
  signature, or a JSON field whose meaning changes. Adding a function, a counter (appended) or an
  optional JSON field does not change it.
- Java's `NativeEngine` refuses to load a library whose `apiVersion()` differs from
  `AdBlockEngine.API_VERSION`; C hosts should do the same with `OAB_API_VERSION`.
- Hosts pin a core commit (git submodule) or release tag; the engine `VERSION` is shown in the
  app's About screen.
