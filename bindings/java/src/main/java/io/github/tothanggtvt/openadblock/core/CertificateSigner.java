package io.github.tothanggtvt.openadblock.core;

/**
 * Signs with the root CA private key the host keeps in its secure store (Android Keystore, macOS
 * Keychain, Windows CNG). The engine never sees the key.
 *
 * <p>Algorithm: ECDSA P-256 with SHA-256, DER encoded signature ({@code SHA256withECDSA} in JCA).
 * Input is at most 8192 bytes. Return {@code null} to refuse.
 */
@FunctionalInterface
public interface CertificateSigner {
    byte[] sign(byte[] data);
}
