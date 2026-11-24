package io.github.tothanggtvt.openadblock.core;

import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * Desktop JVM smoke test of the public Java API against the host build of the JNI library: the
 * path a macOS/Windows/Linux JVM app takes. Run with scripts/test-jvm.sh.
 */
public final class NativeEngineSmokeTest {
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) throws Exception {
        AdBlockEngine engine = NativeEngine.load(Path.of(args[0]));
        check(engine.apiVersion() == AdBlockEngine.API_VERSION, "api version");
        check(!engine.version().isEmpty(), "version");
        check(engine.replaceRules("||ads.example^", "", "", false).contains("\"loaded\":1"), "rules");
        check(engine.configureDns("{}"), "dns config");
        check(!engine.configurePolicy("not json"), "invalid policy rejected");
        check(engine.counters().packetsIn() == 0, "idle counters");

        packetModeRelaysUdp(engine);
        hostKeyCreatesRootCa(engine);
        System.out.println("JVM smoke test passed on " + System.getProperty("os.name"));
    }

    private static void packetModeRelaysUdp(AdBlockEngine engine) throws Exception {
        try (DatagramSocket echo = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            echo.setSoTimeout(5000);
            Thread server = new Thread(() -> {
                byte[] buffer = new byte[2048];
                try {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    echo.receive(packet);
                    echo.send(new DatagramPacket(packet.getData(), packet.getLength(), packet.getSocketAddress()));
                } catch (Exception ignored) {
                }
            });
            server.start();
            LinkedBlockingQueue<byte[]> replies = new LinkedBlockingQueue<>();
            check(engine.startPackets(fd -> true, null, replies::add), "start packets");
            check(engine.isRunning(), "running");
            AppProxyEndpoint proxy = engine.openAppProxy();
            check(proxy != null && proxy.port() > 0 && proxy.token().length() == 32, "app proxy");
            byte[] payload = "ping from the JVM".getBytes(StandardCharsets.UTF_8);
            check(engine.sendPacket(ipv4Udp(40000, echo.getLocalPort(), payload)), "send packet");
            byte[] answer = null;
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (answer == null && System.nanoTime() < deadline) {
                byte[] packet = replies.poll(100, TimeUnit.MILLISECONDS);
                if (packet != null && packet.length >= 28 && packet[9] == 17) {
                    int headerLength = (packet[0] & 0x0f) * 4;
                    answer = Arrays.copyOfRange(packet, headerLength + 8, packet.length);
                }
            }
            check(Arrays.equals(answer, payload), "echoed payload");
            check(engine.counters().udpOpened() >= 1, "udp counter");
            engine.stop();
            check(!engine.isRunning(), "stopped");
            server.join();
        }
    }

    /** IPv4/UDP from the virtual address 172.19.0.1 to 127.0.0.1; UDP checksum 0 (optional). */
    private static byte[] ipv4Udp(int sourcePort, int destinationPort, byte[] payload) {
        int length = 28 + payload.length;
        byte[] packet = new byte[length];
        packet[0] = 0x45;
        packet[2] = (byte) (length >> 8);
        packet[3] = (byte) length;
        packet[8] = 64;
        packet[9] = 17;
        byte[] addresses = {(byte) 172, 19, 0, 1, 127, 0, 0, 1};
        System.arraycopy(addresses, 0, packet, 12, 8);
        int sum = 0;
        for (int i = 0; i < 20; i += 2) sum += ((packet[i] & 0xff) << 8) | (packet[i + 1] & 0xff);
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        packet[10] = (byte) (~sum >> 8);
        packet[11] = (byte) ~sum;
        packet[20] = (byte) (sourcePort >> 8);
        packet[21] = (byte) sourcePort;
        packet[22] = (byte) (destinationPort >> 8);
        packet[23] = (byte) destinationPort;
        packet[24] = (byte) ((8 + payload.length) >> 8);
        packet[25] = (byte) (8 + payload.length);
        System.arraycopy(payload, 0, packet, 28, payload.length);
        return packet;
    }

    private static void hostKeyCreatesRootCa(AdBlockEngine engine) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair key = generator.generateKeyPair();
        CertificateSigner signer = data -> {
            try {
                Signature signature = Signature.getInstance("SHA256withECDSA");
                signature.initSign(key.getPrivate());
                signature.update(data);
                return signature.sign();
            } catch (Exception e) {
                return null;
            }
        };
        ECPublicKey publicKey = (ECPublicKey) key.getPublic();
        byte[] point = new byte[65];
        point[0] = 4;
        copyUnsigned(publicKey.getW().getAffineX(), point, 1);
        copyUnsigned(publicKey.getW().getAffineY(), point, 33);
        byte[] certificate = engine.generateRootCa(signer, point);
        check(certificate != null && certificate.length > 100, "root CA");
        check(engine.setRootCa(signer, point, certificate), "install root CA");
        check(engine.generateRootCa(data -> null, point) == null, "refusing signer");
        engine.clearRootCa();
    }

    private static void copyUnsigned(BigInteger value, byte[] target, int offset) {
        byte[] bytes = value.toByteArray();
        int start = Math.max(0, bytes.length - 32);
        int length = bytes.length - start;
        System.arraycopy(bytes, start, target, offset + 32 - length, length);
    }
}
