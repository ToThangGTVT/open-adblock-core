package io.github.tothanggtvt.openadblock.core;

import java.nio.file.Path;
import java.util.Objects;

/** {@link AdBlockEngine} backed by the {@code openadblock_jni} native library. */
public final class NativeEngine implements AdBlockEngine {
    /** {@code System.loadLibrary} name: {@code libopenadblock_jni.so/.dylib}, {@code .dll}. */
    public static final String LIBRARY = "openadblock_jni";

    private static volatile NativeEngine instance;

    private NativeEngine() {}

    /**
     * Loads the library from the default search path (Android APK, {@code java.library.path}) on
     * first use.
     *
     * @throws UnsatisfiedLinkError when the library is missing or implements another API version
     */
    public static NativeEngine get() {
        NativeEngine engine = instance;
        if (engine == null) {
            synchronized (NativeEngine.class) {
                engine = instance;
                if (engine == null) {
                    System.loadLibrary(LIBRARY);
                    engine = instance = checked();
                }
            }
        }
        return engine;
    }

    /** Desktop hosts: loads the library from an explicit file (once per process). */
    public static NativeEngine load(Path library) {
        Objects.requireNonNull(library, "library");
        synchronized (NativeEngine.class) {
            if (instance == null) {
                System.load(library.toAbsolutePath().toString());
                instance = checked();
            }
            return instance;
        }
    }

    private static NativeEngine checked() {
        int native_ = NativeBindings.apiVersion();
        if (native_ != API_VERSION) {
            throw new UnsatisfiedLinkError(
                    "openadblock_jni implements API " + native_ + ", this binding needs " + API_VERSION);
        }
        return new NativeEngine();
    }

    @Override public String version() { return NativeBindings.version(); }

    @Override public int apiVersion() { return NativeBindings.apiVersion(); }

    @Override
    public boolean start(int fd, SocketProtector protector, String dns) {
        Objects.requireNonNull(protector, "protector");
        return NativeBindings.startFd(fd, protector, dns == null ? "" : dns);
    }

    @Override
    public boolean startPackets(SocketProtector protector, String dns, PacketSink sink) {
        Objects.requireNonNull(protector, "protector");
        Objects.requireNonNull(sink, "sink");
        return NativeBindings.startPackets(protector, dns == null ? "" : dns, sink);
    }

    @Override
    public boolean sendPacket(byte[] packet, int offset, int length) {
        Objects.checkFromIndexSize(offset, length, packet.length);
        return NativeBindings.sendPacket(packet, offset, length);
    }

    @Override
    public AppProxyEndpoint openAppProxy() {
        String value = NativeBindings.openAppProxy();
        if (value == null) return null;
        int space = value.indexOf(' ');
        return new AppProxyEndpoint(Integer.parseInt(value.substring(0, space)), value.substring(space + 1));
    }

    @Override public void stop() { NativeBindings.stop(); }

    @Override
    public boolean updateNetwork(String dns) {
        return NativeBindings.updateNetwork(dns == null ? "" : dns);
    }

    @Override public boolean isRunning() { return NativeBindings.isRunning(); }

    @Override public TrafficCounters counters() { return new TrafficCounters(NativeBindings.counters()); }

    @Override
    public String replaceRules(String dnsRules, String browserRules, String customRules, boolean apply) {
        return NativeBindings.replaceRules(
                Objects.requireNonNull(dnsRules), Objects.requireNonNull(browserRules),
                Objects.requireNonNull(customRules), apply);
    }

    @Override
    public String setResources(String scriptlets, String redirects) {
        return NativeBindings.setResources(Objects.requireNonNull(scriptlets), Objects.requireNonNull(redirects));
    }

    @Override public boolean configurePolicy(String json) { return NativeBindings.configurePolicy(Objects.requireNonNull(json)); }

    @Override public boolean configureDns(String json) { return NativeBindings.configureDns(Objects.requireNonNull(json)); }

    @Override public boolean configureHttps(String json) { return NativeBindings.configureHttps(Objects.requireNonNull(json)); }

    @Override public void setEventListener(EngineEventListener listener) { NativeBindings.setEventListener(listener); }

    @Override public void flushEvents() { NativeBindings.flushEvents(); }

    @Override
    public void setRequestCapture(int app, long session, int minutes) {
        NativeBindings.setRequestCapture(app, session, minutes);
    }

    @Override
    public byte[] generateRootCa(CertificateSigner signer, byte[] publicPoint) {
        return NativeBindings.generateRootCa(Objects.requireNonNull(signer), Objects.requireNonNull(publicPoint));
    }

    @Override
    public boolean setRootCa(CertificateSigner signer, byte[] publicPoint, byte[] certificate) {
        return NativeBindings.setRootCa(
                Objects.requireNonNull(signer), Objects.requireNonNull(publicPoint), Objects.requireNonNull(certificate));
    }

    @Override public void clearRootCa() { NativeBindings.setRootCa(null, new byte[0], new byte[0]); }
}
