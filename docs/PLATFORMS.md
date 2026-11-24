# Platforms

| Platform | Binding | Packet I/O | Protect | App id | Status |
| --- | --- | --- | --- | --- | --- |
| Android 13+ | Java API (JNI) | TUN fd from `VpnService` | `VpnService.protect` | UID via `getConnectionOwnerUid` | **Shipping** (Open AdBlock app) |
| Desktop JVM (macOS/Linux) | Java API (JNI) | fd or packet mode | host-specific | host-specific | Builds and passes `scripts/test-jvm.sh` |
| macOS (Network Extension) | C ABI from Swift | packet mode (`NEPacketTunnelFlow`) | return `true` (extension sockets bypass the tunnel) | not available per packet; -1 | Engine builds and tests on macOS; host app not written |
| Linux | C ABI or JVM | TUN fd | `SO_MARK` + policy routing | `/proc/net` lookup | Engine builds and tests on Linux CI; host not written |
| Windows | C ABI from C#/C++ | packet mode (Wintun) | bind to physical interface (`IP_UNICAST_IF`) | PID via `GetExtendedTcpTable` | **Not yet**: engine needs a Windows socket layer |
| iOS | C ABI from Swift | packet mode | as macOS | -1 | Not yet: memory budget of the extension (50 MB) to verify |

## macOS host sketch (Swift)

```swift
final class Tunnel: NEPacketTunnelProvider {
    override func startTunnel(options: [String: NSObject]?) async throws {
        try await setTunnelNetworkSettings(settings)          // 172.19.0.1/30, DNS 172.19.0.2
        var protector = OabSocketProtector(context: nil, protect: { _, _ in true },
                                           connection_owner: nil, release: nil)
        var sink = OabPacketSink(context: Unmanaged.passRetained(packetFlow).toOpaque(),
            on_packet: { ctx, data, len in
                let flow = Unmanaged<NEPacketTunnelFlow>.fromOpaque(ctx!).takeUnretainedValue()
                let packet = Data(bytes: data!, count: len)
                flow.writePackets([packet], withProtocols: [packet.first! >> 4 == 6 ? AF_INET6 : AF_INET] as [NSNumber])
            },
            release: { ctx in Unmanaged<NEPacketTunnelFlow>.fromOpaque(ctx!).release() })
        guard oab_start_packets(&protector, "", &sink) else { throw TunnelError.start }
        readLoop()
    }
    func readLoop() {
        packetFlow.readPackets { packets, _ in
            for p in packets { p.withUnsafeBytes { _ = oab_send_packet($0.baseAddress, p.count) } }
            self.readLoop()
        }
    }
}
```

## Windows work list

The engine compiles on Unix only today. To add Windows:

1. `sockets`, `tcp`, `udp`, `dpi`: replace `RawFd`/`AsRawFd` with a small `SocketHandle`
   abstraction (`RawSocket` on Windows) and move the Linux-only `dpi` tricks behind `cfg`.
2. `tun`: compile only the `Packets` form on Windows (the `Fd` form is already `cfg(unix)` at the
   API level).
3. Protector: bind each socket to the physical interface index before connect.
4. CI: add a `windows-latest` job running `cargo test` and `scripts/test-c.sh` (MSVC).

The public API (Java, C, JSON) does not change for any of this.
