package io.github.tothanggtvt.openadblock.core;

/**
 * Receives IP packets the engine sends toward apps when the host drives packet I/O (see {@link
 * TunnelController#startPackets}). Write the packet to the virtual interface (Wintun, utun,
 * NEPacketTunnelFlow) and return quickly. The array is owned by the receiver.
 */
@FunctionalInterface
public interface PacketSink {
    void onPacket(byte[] packet);
}
