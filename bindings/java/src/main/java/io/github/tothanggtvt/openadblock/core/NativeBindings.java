package io.github.tothanggtvt.openadblock.core;

/**
 * JNI declarations. Names and descriptors are the contract with {@code crates/jni}; {@code
 * scripts/check-jni-exports.py} fails the build when they drift apart.
 */
final class NativeBindings {
    private NativeBindings() {}

    static native String version();

    static native int apiVersion();

    static native boolean startFd(int fd, SocketProtector protector, String dns);

    static native boolean startPackets(SocketProtector protector, String dns, PacketSink sink);

    static native boolean sendPacket(byte[] packet, int offset, int length);

    static native String openAppProxy();

    static native void stop();

    static native boolean updateNetwork(String dns);

    static native boolean isRunning();

    static native long[] counters();

    static native boolean configurePolicy(String json);

    static native boolean configureDns(String json);

    static native boolean configureHttps(String json);

    static native String replaceRules(String dns, String browser, String custom, boolean apply);

    static native String setResources(String scriptlets, String redirects);

    static native void setEventListener(EngineEventListener listener);

    static native void flushEvents();

    static native void setRequestCapture(int app, long session, int minutes);

    static native byte[] generateRootCa(CertificateSigner signer, byte[] publicPoint);

    static native boolean setRootCa(CertificateSigner signer, byte[] publicPoint, byte[] certificate);
}
