import Foundation

// The Swift face of the Open AdBlock core. The protocols mirror the Java API in bindings/java
// one to one, so Android, desktop JVM and Apple hosts share one mental model. JSON schemas and
// semantics: docs/API.md.

/// Host hook for every outbound socket the engine opens. Called on engine threads before
/// connect/bind/send; must be thread-safe and fast. Returning `false` closes the socket.
///
/// In a macOS/iOS packet tunnel provider the extension's own sockets already bypass the tunnel,
/// so `protect` may simply return `true` (optionally binding the socket to the physical
/// interface).
public protocol SocketProtector: AnyObject {
    func protect(socket: Int64) -> Bool
    /// App owning a tunnelled flow, or `nil` when unknown (packet tunnels cannot tell).
    func connectionOwner(
        protocol: UInt8, source: String, sourcePort: UInt16, destination: String,
        destinationPort: UInt16
    ) -> Int64?
}

extension SocketProtector {
    public func connectionOwner(
        protocol: UInt8, source: String, sourcePort: UInt16, destination: String,
        destinationPort: UInt16
    ) -> Int64? { nil }
}

/// Batched query-log/statistics JSON, at most every five seconds, on a full batch and on stop.
/// Called on an engine thread: hand the string off and return.
public protocol EngineEventListener: AnyObject {
    func onEvents(_ json: String)
}

/// One IP packet from the engine toward apps (packet mode). Write it to the virtual interface
/// (`NEPacketTunnelFlow.writePackets`) and return quickly.
public protocol PacketSink: AnyObject {
    func onPacket(_ packet: Data)
}

/// Signs with the root CA key the host keeps (Keychain/Secure Enclave): ECDSA P-256 with
/// SHA-256, DER signature. Input is at most 8192 bytes. Return `nil` to refuse.
public protocol CertificateSigner: AnyObject {
    func sign(_ data: Data) -> Data?
}

/// Lifecycle of the full tunnel. One tunnel per process.
public protocol TunnelController {
    /// Starts on a TUN descriptor the engine then owns (closed on every path).
    func start(fileDescriptor: Int32, protector: SocketProtector, dns: String?) -> Bool
    /// Starts with host-driven packet I/O; feed packets with `send(packet:)`.
    func startPackets(protector: SocketProtector, dns: String?, sink: PacketSink) -> Bool
    /// Queues one packet read from the virtual interface; `false` when not running in packet
    /// mode or the queue is full (the packet is dropped).
    @discardableResult func send(packet: Data) -> Bool
    func stop()
    /// Physical network changed: upstream sockets are dropped, new flows use `dns`.
    @discardableResult func updateNetwork(dns: String?) -> Bool
    var isRunning: Bool { get }
    var counters: TrafficCounters { get }
}

/// Filter lists and scriptlet resources. Changes apply to new requests immediately.
public protocol FilterController {
    /// `dns` lists feed the domain matcher, `browser` lists only decrypted HTTPS, `custom` both.
    /// With `apply` false the lists are only validated.
    func replaceRules(dns: String, browser: String, custom: String, apply: Bool) -> RuleReport
    /// AdGuard Scriptlets resources; returns the engine's JSON result.
    func setResources(scriptlets: String, redirects: String) -> String
}

/// JSON configuration, valid before `start` and while running. `false` keeps the old value.
public protocol EngineConfiguration {
    @discardableResult func configurePolicy(json: String) -> Bool
    @discardableResult func configureDNS(json: String) -> Bool
    @discardableResult func configureHTTPS(json: String) -> Bool
}

/// Query log, statistics and request capture.
public protocol EventController {
    /// Replaces the listener; `nil` detaches it.
    func setEventListener(_ listener: EngineEventListener?)
    func flushEvents()
    func setRequestCapture(app: Int32, session: Int64, minutes: Int32)
}

/// Root CA for opt-in HTTPS filtering; the private key never leaves the host's key store.
public protocol CertificateAuthority {
    /// `publicPoint`: uncompressed P-256 point (65 bytes, 0x04 first). Returns DER.
    func generateRootCA(signer: CertificateSigner, publicPoint: Data) -> Data?
    @discardableResult
    func setRootCA(signer: CertificateSigner, publicPoint: Data, certificate: Data) -> Bool
    func clearRootCA()
}

/// Entry point of the Open AdBlock core for Swift hosts. Use `NativeEngine.shared`.
public protocol AdBlockEngine: TunnelController, FilterController, EngineConfiguration,
    EventController, CertificateAuthority
{
    /// Engine release, `MAJOR.MINOR.PATCH`.
    var version: String { get }
    /// Binding contract implemented by the linked library.
    var apiVersion: UInt32 { get }
}

/// The binding contract these Swift declarations were written against.
public let openAdBlockAPIVersion: UInt32 = 1

/// Traffic counters since the tunnel started; zero while stopped.
public struct TrafficCounters: Equatable, Sendable {
    public var packetsIn: Int64 = 0
    public var packetsOut: Int64 = 0
    public var tcpOpened: Int64 = 0
    public var udpOpened: Int64 = 0
    /// Sockets the protector refused; their flows were dropped.
    public var protectDenied: Int64 = 0
    public var tcpBytesUp: Int64 = 0
    public var tcpBytesDown: Int64 = 0
    public var networkResets: Int64 = 0

    public init() {}

    init(_ values: [Int64]) {
        let v = values + Array(repeating: 0, count: max(0, 8 - values.count))
        (packetsIn, packetsOut, tcpOpened, udpOpened) = (v[0], v[1], v[2], v[3])
        (protectDenied, tcpBytesUp, tcpBytesDown, networkResets) = (v[4], v[5], v[6], v[7])
    }
}

/// Result of compiling filter lists.
public struct RuleReport: Decodable, Equatable, Sendable {
    public struct LineError: Decodable, Equatable, Sendable {
        public var line: Int
        public var message: String
    }
    public var loaded: Int
    public var ignored: Int
    public var errors: [LineError]
}
