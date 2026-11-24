package io.github.tothanggtvt.openadblock.core;

/**
 * Entry point of the Open AdBlock core for JVM hosts (Android, desktop).
 *
 * <p>Obtain the native implementation with {@link NativeEngine#get()}. Code that depends on this
 * interface instead of {@link NativeEngine} can be unit-tested with a fake.
 *
 * <p>All methods are thread-safe. Callbacks arrive on engine threads.
 */
public interface AdBlockEngine
        extends TunnelController,
                FilterController,
                EngineConfiguration,
                EventController,
                CertificateAuthority {
    /**
     * The binding contract this Java API was written against. {@link NativeEngine} refuses to
     * load a native library with a different {@link #apiVersion()}.
     */
    int API_VERSION = 1;

    /** Native engine release, {@code MAJOR.MINOR.PATCH}. */
    String version();

    /** Binding contract implemented by the native library. */
    int apiVersion();
}
