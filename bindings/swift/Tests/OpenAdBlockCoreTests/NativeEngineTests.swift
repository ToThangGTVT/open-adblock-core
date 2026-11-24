import CryptoKit
import Foundation
import XCTest

@testable import OpenAdBlockCore

private final class Allow: SocketProtector {
    func protect(socket: Int64) -> Bool { true }
}

private final class Collect: PacketSink, @unchecked Sendable {
    private let lock = NSLock()
    private var packets: [Data] = []
    func onPacket(_ packet: Data) {
        lock.lock()
        packets.append(packet)
        lock.unlock()
    }
    func drain() -> [Data] {
        lock.lock()
        defer { lock.unlock() }
        let out = packets
        packets = []
        return out
    }
}

private final class KeySigner: CertificateSigner {
    let key = P256.Signing.PrivateKey()
    func sign(_ data: Data) -> Data? { try? key.signature(for: data).derRepresentation }
}

private final class Refuse: CertificateSigner {
    func sign(_ data: Data) -> Data? { nil }
}

/// IPv4/UDP from the virtual address 172.19.0.1 to 127.0.0.1; UDP checksum 0 (optional).
private func ipv4UDP(source: UInt16, destination: UInt16, payload: [UInt8]) -> Data {
    var packet = [UInt8](repeating: 0, count: 28) + payload
    let length = packet.count
    packet[0] = 0x45
    packet[2] = UInt8(length >> 8)
    packet[3] = UInt8(length & 0xff)
    packet[8] = 64
    packet[9] = 17
    packet.replaceSubrange(12..<20, with: [172, 19, 0, 1, 127, 0, 0, 1])
    var sum = 0
    for i in stride(from: 0, to: 20, by: 2) { sum += Int(packet[i]) << 8 | Int(packet[i + 1]) }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
    packet[10] = UInt8((~sum >> 8) & 0xff)
    packet[11] = UInt8(~sum & 0xff)
    packet[20] = UInt8(source >> 8)
    packet[21] = UInt8(source & 0xff)
    packet[22] = UInt8(destination >> 8)
    packet[23] = UInt8(destination & 0xff)
    packet[24] = UInt8((8 + payload.count) >> 8)
    packet[25] = UInt8((8 + payload.count) & 0xff)
    return Data(packet)
}

/// Loopback UDP echo server on a POSIX socket; returns its port.
private func startEcho() -> UInt16 {
    let fd = socket(AF_INET, SOCK_DGRAM, 0)
    var address = sockaddr_in()
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1")
    var size = socklen_t(MemoryLayout<sockaddr_in>.size)
    withUnsafeMutablePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            _ = bind(fd, $0, size)
            _ = getsockname(fd, $0, &size)
        }
    }
    Thread.detachNewThread {
        var buffer = [UInt8](repeating: 0, count: 2048)
        var peer = sockaddr_storage()
        var peerSize = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let count = withUnsafeMutablePointer(to: &peer) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                recvfrom(fd, &buffer, buffer.count, 0, $0, &peerSize)
            }
        }
        if count > 0 {
            withUnsafePointer(to: &peer) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    _ = sendto(fd, buffer, count, 0, $0, peerSize)
                }
            }
        }
        close(fd)
    }
    return UInt16(bigEndian: address.sin_port)
}

final class NativeEngineTests: XCTestCase {
    func testPacketModeRelaysUDPAndRootCA() throws {
        let engine = try XCTUnwrap(NativeEngine.shared)
        XCTAssertEqual(engine.apiVersion, openAdBlockAPIVersion)
        XCTAssertFalse(engine.version.isEmpty)
        XCTAssertEqual(engine.replaceRules(dns: "||ads.example^", browser: "", custom: "", apply: false).loaded, 1)
        XCTAssertTrue(engine.configureDNS(json: "{}"))
        XCTAssertFalse(engine.configurePolicy(json: "not json"))

        // Packet mode, as a NEPacketTunnelProvider drives it.
        let port = startEcho()
        let sink = Collect()
        XCTAssertTrue(engine.startPackets(protector: Allow(), dns: nil, sink: sink))
        XCTAssertTrue(engine.isRunning)
        let payload = Array("ping from Swift".utf8)
        XCTAssertTrue(engine.send(packet: ipv4UDP(source: 40000, destination: port, payload: payload)))
        var echoed: [UInt8]?
        let deadline = Date().addingTimeInterval(5)
        while echoed == nil, Date() < deadline {
            for packet in sink.drain() where packet.count >= 28 && packet[9] == 17 {
                let header = Int(packet[0] & 0x0f) * 4
                echoed = Array(packet[(header + 8)...])
            }
            Thread.sleep(forTimeInterval: 0.05)
        }
        XCTAssertEqual(echoed, payload)
        XCTAssertGreaterThanOrEqual(engine.counters.udpOpened, 1)
        engine.stop()
        XCTAssertFalse(engine.isRunning)
        XCTAssertEqual(engine.counters, TrafficCounters())

        // Root CA with a CryptoKit key the engine never sees.
        let signer = KeySigner()
        let point = signer.key.publicKey.x963Representation
        let certificate = try XCTUnwrap(engine.generateRootCA(signer: signer, publicPoint: point))
        XCTAssertGreaterThan(certificate.count, 100)
        XCTAssertTrue(engine.setRootCA(signer: signer, publicPoint: point, certificate: certificate))
        XCTAssertNil(engine.generateRootCA(signer: Refuse(), publicPoint: point))
        engine.clearRootCA()
    }
}
