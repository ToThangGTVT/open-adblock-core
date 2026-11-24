package io.github.tothanggtvt.openadblock.core;

import java.util.Arrays;

/** Traffic counters since the tunnel started. All zero while stopped. */
public final class TrafficCounters {
    /** Number of values in {@link #toArray()}; new counters are only ever appended. */
    public static final int SIZE = 8;

    private final long[] values;

    TrafficCounters(long[] values) {
        this.values = Arrays.copyOf(values == null ? new long[0] : values, SIZE);
    }

    public long packetsIn() { return values[0]; }

    public long packetsOut() { return values[1]; }

    public long tcpOpened() { return values[2]; }

    public long udpOpened() { return values[3]; }

    /** Sockets the {@link SocketProtector} refused; the flows were dropped. */
    public long protectDenied() { return values[4]; }

    public long tcpBytesUp() { return values[5]; }

    public long tcpBytesDown() { return values[6]; }

    /** Completed {@link TunnelController#updateNetwork} calls. */
    public long networkResets() { return values[7]; }

    /** Values in declaration order; a copy. */
    public long[] toArray() { return values.clone(); }

    @Override
    public String toString() { return "TrafficCounters" + Arrays.toString(values); }
}
