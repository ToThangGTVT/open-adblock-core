package io.github.tothanggtvt.openadblock.core;

/**
 * JSON configuration, valid before {@code start} and while running. Each call replaces that
 * section completely; unknown fields are ignored and missing fields take defaults. On invalid
 * input the call returns {@code false} and the previous configuration stays active. Schemas:
 * {@code docs/API.md}.
 */
public interface EngineConfiguration {
    /** Per-app filtering/bypass, firewall, IPv6 and DPI circumvention. */
    boolean configurePolicy(String json);

    /** Upstreams (UDP/DoH/DoT/DoQ), block response mode, cache and logging. */
    boolean configureDns(String json);

    /** HTTPS filtering scope: which apps and domains may be decrypted. Off by default. */
    boolean configureHttps(String json);
}
