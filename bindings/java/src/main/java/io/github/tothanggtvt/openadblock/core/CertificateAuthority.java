package io.github.tothanggtvt.openadblock.core;

/**
 * Root CA for opt-in HTTPS filtering. The private key stays in the host's secure store and is
 * used only through {@link CertificateSigner}. Without a root CA, HTTPS is never decrypted.
 */
public interface CertificateAuthority {
    /**
     * Creates a self-signed root certificate for the host key.
     *
     * @param publicPoint uncompressed P-256 public point, 65 bytes starting with {@code 0x04}
     * @return DER certificate, or {@code null} when signing failed
     */
    byte[] generateRootCa(CertificateSigner signer, byte[] publicPoint);

    /** Installs the root CA; {@code false} when the certificate does not match the key. */
    boolean setRootCa(CertificateSigner signer, byte[] publicPoint, byte[] certificate);

    /** Removes the root CA, turning HTTPS filtering off. */
    void clearRootCa();
}
