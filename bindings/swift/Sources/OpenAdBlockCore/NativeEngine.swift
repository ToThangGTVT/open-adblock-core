import COpenAdBlock
import Foundation

/// `AdBlockEngine` backed by the statically linked C ABI (`libopenadblock`).
public final class NativeEngine: AdBlockEngine, @unchecked Sendable {
    /// The process-wide engine, or `nil` when the linked library implements another API version.
    public static let shared: NativeEngine? =
        oab_api_version() == openAdBlockAPIVersion ? NativeEngine() : nil

    private init() {}

    public var version: String { String(cString: oab_version()) }
    public var apiVersion: UInt32 { oab_api_version() }

    // MARK: Tunnel

    public func start(fileDescriptor: Int32, protector: SocketProtector, dns: String?) -> Bool {
        var native = Self.native(protector)
        return oab_start_fd(fileDescriptor, &native, dns ?? "")
    }

    public func startPackets(protector: SocketProtector, dns: String?, sink: PacketSink) -> Bool {
        var nativeProtector = Self.native(protector)
        var nativeSink = OabPacketSink(
            context: Box.retain(sink),
            on_packet: { context, data, length in
                guard let data else { return }
                Box.value(context, as: PacketSink.self).onPacket(Data(bytes: data, count: length))
            },
            release: Box.release)
        return oab_start_packets(&nativeProtector, dns ?? "", &nativeSink)
    }

    @discardableResult
    public func send(packet: Data) -> Bool {
        packet.withUnsafeBytes { bytes in
            guard let base = bytes.bindMemory(to: UInt8.self).baseAddress else { return false }
            return oab_send_packet(base, bytes.count)
        }
    }

    public func stop() { oab_stop() }

    @discardableResult
    public func updateNetwork(dns: String?) -> Bool { oab_update_network(dns ?? "") }

    public var isRunning: Bool { oab_is_running() }

    public var counters: TrafficCounters {
        var values = [Int64](repeating: 0, count: Int(OAB_COUNTER_COUNT))
        let count = values.withUnsafeMutableBufferPointer {
            oab_counters($0.baseAddress, $0.count)
        }
        return TrafficCounters(Array(values.prefix(count)))
    }

    // MARK: Filters

    public func replaceRules(dns: String, browser: String, custom: String, apply: Bool)
        -> RuleReport
    {
        let json = Self.take(oab_replace_rules(dns, browser, custom, apply)) ?? ""
        return (try? JSONDecoder().decode(RuleReport.self, from: Data(json.utf8)))
            ?? RuleReport(loaded: 0, ignored: 0, errors: [])
    }

    public func setResources(scriptlets: String, redirects: String) -> String {
        Self.take(oab_set_resources(scriptlets, redirects)) ?? #"{"error":"invalid input"}"#
    }

    // MARK: Configuration

    @discardableResult public func configurePolicy(json: String) -> Bool {
        oab_configure_policy(json)
    }
    @discardableResult public func configureDNS(json: String) -> Bool { oab_configure_dns(json) }
    @discardableResult public func configureHTTPS(json: String) -> Bool {
        oab_configure_https(json)
    }

    // MARK: Events

    public func setEventListener(_ listener: EngineEventListener?) {
        guard let listener else {
            oab_set_event_listener(nil)
            return
        }
        var native = OabEventListener(
            context: Box.retain(listener),
            on_events: { context, json in
                guard let json else { return }
                Box.value(context, as: EngineEventListener.self).onEvents(String(cString: json))
            },
            release: Box.release)
        oab_set_event_listener(&native)
    }

    public func flushEvents() { oab_flush_events() }

    public func setRequestCapture(app: Int32, session: Int64, minutes: Int32) {
        oab_set_request_capture(app, session, minutes)
    }

    // MARK: Certificate authority

    public func generateRootCA(signer: CertificateSigner, publicPoint: Data) -> Data? {
        var native = Self.native(signer)
        var certificate: UnsafeMutablePointer<UInt8>?
        var length = 0
        let created = publicPoint.withUnsafeBytes { point in
            oab_generate_root_ca(
                &native, point.bindMemory(to: UInt8.self).baseAddress, point.count,
                &certificate, &length)
        }
        guard created, let certificate else { return nil }
        defer { oab_bytes_free(certificate, length) }
        return Data(bytes: certificate, count: length)
    }

    @discardableResult
    public func setRootCA(signer: CertificateSigner, publicPoint: Data, certificate: Data) -> Bool {
        var native = Self.native(signer)
        return publicPoint.withUnsafeBytes { point in
            certificate.withUnsafeBytes { der in
                oab_set_root_ca(
                    &native, point.bindMemory(to: UInt8.self).baseAddress, point.count,
                    der.bindMemory(to: UInt8.self).baseAddress, der.count)
            }
        }
    }

    public func clearRootCA() { _ = oab_set_root_ca(nil, nil, 0, nil, 0) }

    // MARK: Bridging

    private static func take(_ value: UnsafeMutablePointer<CChar>?) -> String? {
        guard let value else { return nil }
        defer { oab_string_free(value) }
        return String(cString: value)
    }

    private static func native(_ protector: SocketProtector) -> OabSocketProtector {
        OabSocketProtector(
            context: Box.retain(protector),
            protect: { context, socket in
                Box.value(context, as: SocketProtector.self).protect(socket: socket)
            },
            connection_owner: { context, proto, source, sourcePort, destination, destinationPort in
                guard let source, let destination else { return -1 }
                return Box.value(context, as: SocketProtector.self).connectionOwner(
                    protocol: proto, source: String(cString: source), sourcePort: sourcePort,
                    destination: String(cString: destination), destinationPort: destinationPort)
                    ?? -1
            },
            release: Box.release)
    }

    private static func native(_ signer: CertificateSigner) -> OabCertificateSigner {
        OabCertificateSigner(
            context: Box.retain(signer),
            sign: { context, data, length, output, capacity in
                guard let data, let output else { return 0 }
                let input = Data(bytes: data, count: length)
                guard let signature = Box.value(context, as: CertificateSigner.self).sign(input),
                    !signature.isEmpty, signature.count <= capacity
                else { return 0 }
                signature.copyBytes(to: output, count: signature.count)
                return signature.count
            },
            release: Box.release)
    }
}

/// Carries a Swift object through a C `void *context`; the engine calls `release` exactly once.
/// Not generic: C function pointers cannot capture generic parameters.
private final class Box {
    let value: AnyObject
    init(_ value: AnyObject) { self.value = value }

    static func retain(_ value: AnyObject) -> UnsafeMutableRawPointer {
        Unmanaged.passRetained(Box(value)).toOpaque()
    }
    static func value<T>(_ context: UnsafeMutableRawPointer?, as _: T.Type) -> T {
        Unmanaged<Box>.fromOpaque(context!).takeUnretainedValue().value as! T
    }
    static let release: @convention(c) (UnsafeMutableRawPointer?) -> Void = { context in
        guard let context else { return }
        Unmanaged<Box>.fromOpaque(context).release()
    }
}
