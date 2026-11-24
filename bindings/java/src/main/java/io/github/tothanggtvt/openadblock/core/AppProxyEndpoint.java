package io.github.tothanggtvt.openadblock.core;

import java.util.Objects;

/**
 * Loopback listener for host-intercepted app streams. Per TCP connection to {@code
 * 127.0.0.1:port} send {@code "OAB1 <token> <host> <port> <app id>\n"}, then relay the app's
 * bytes both ways.
 */
public final class AppProxyEndpoint {
    private final int port;
    private final String token;

    AppProxyEndpoint(int port, String token) {
        this.port = port;
        this.token = Objects.requireNonNull(token);
    }

    public int port() { return port; }

    /** Random per tunnel run; keep it in-process. */
    public String token() { return token; }

    @Override
    public boolean equals(Object other) {
        return other instanceof AppProxyEndpoint that && port == that.port && token.equals(that.token);
    }

    @Override
    public int hashCode() { return Objects.hash(port, token); }

    @Override
    public String toString() { return "AppProxyEndpoint[port=" + port + "]"; }
}
