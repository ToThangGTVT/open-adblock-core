package io.github.tothanggtvt.openadblock.core;

/**
 * Host hook for every outbound socket the engine opens.
 *
 * <p>Called on engine threads, before connect/bind/send. Implementations must be thread-safe and
 * fast. Returning {@code false} (or throwing) makes the engine close the socket: the engine fails
 * closed, so traffic can never loop back into the tunnel.
 *
 * <ul>
 *   <li>Android: {@code VpnService.protect(fd)} already has this signature.
 *   <li>macOS Network Extension: sockets of the extension bypass the tunnel; return {@code true}.
 *   <li>Windows: bind the socket to the physical interface ({@code IP_UNICAST_IF}).
 * </ul>
 */
public interface SocketProtector {
    /** Excludes the socket {@code fd} from the tunnel. */
    boolean protect(int fd);

    /**
     * Identifies the app that owns a tunnelled connection, for per-app policy and logs.
     *
     * @param protocol IP protocol number (6 TCP, 17 UDP)
     * @return Android UID, Windows PID or any other stable non-negative app id; {@code -1} when
     *     unknown
     */
    default int connectionOwner(
            int protocol, String source, int sourcePort, String destination, int destinationPort) {
        return -1;
    }
}
