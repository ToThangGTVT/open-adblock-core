package io.github.tothanggtvt.openadblock.core;

/**
 * Lifecycle of the full tunnel. One tunnel per process.
 *
 * <p>Two ways to hand packets to the engine:
 *
 * <ul>
 *   <li>{@link #start(int, SocketProtector, String)}: the engine owns a TUN file descriptor
 *       (Android {@code VpnService}, Linux, macOS utun).
 *   <li>{@link #startPackets(SocketProtector, String, PacketSink)}: the host reads/writes packets
 *       itself (Windows Wintun, macOS {@code NEPacketTunnelFlow}) and feeds them with {@link
 *       #sendPacket}.
 * </ul>
 */
public interface TunnelController {
    /**
     * Starts the tunnel on a TUN descriptor. Ownership of {@code fd} passes to the engine on
     * entry, even when this returns {@code false} (Android: pass {@code
     * ParcelFileDescriptor.detachFd()}).
     *
     * @param dns upstream resolver for queries sent to the virtual DNS address, as an IP literal;
     *     {@code null} or empty when only encrypted upstreams from {@code configureDns} are used
     * @return {@code false} if already running or startup failed
     */
    boolean start(int fd, SocketProtector protector, String dns);

    /** Starts the tunnel with host-driven packet I/O. */
    boolean startPackets(SocketProtector protector, String dns, PacketSink sink);

    /**
     * Queues one IP packet read from the virtual interface (packet mode only).
     *
     * @return {@code false} when not running in packet mode or the queue is full (the packet is
     *     dropped, as a congested link would)
     */
    boolean sendPacket(byte[] packet, int offset, int length);

    default boolean sendPacket(byte[] packet) {
        return sendPacket(packet, 0, packet.length);
    }

    /**
     * Opens the loopback listener through which the host hands over TCP streams it intercepts per
     * app, so they get the tunnel's filtering and HTTPS decryption ({@code docs/API.md#app-proxy}).
     *
     * @return the endpoint, or {@code null} when the tunnel is not running
     */
    AppProxyEndpoint openAppProxy();

    /** Stops the tunnel, joins its thread and closes the descriptor. Idempotent. */
    void stop();

    /**
     * Signals a physical network change: upstream sockets are dropped and new flows use {@code
     * dns}. Blocks until applied (normally well under two seconds).
     */
    boolean updateNetwork(String dns);

    /** {@code false} once stopped or after packet I/O failed. */
    boolean isRunning();

    TrafficCounters counters();
}
