import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Manages the ephemeral session keys for sessions between peers
 * uses X25519 for key exchange and HKDF to derive a secure
 * AES-256-GCM key for encrypting messages and files during a session
 */

public class SessionManager {

    private X25519PrivateKeyParameters privateKey;
    private X25519PublicKeyParameters publicKey;
    private byte[] sharedKey;

    public SessionManager() {
        /**
         * on initialization, a new one-time X25519 keypair is generated
         * making sure that each session has a fresh set of unique keys
         */
        X25519KeyPairGenerator keyGen = new X25519KeyPairGenerator();
        keyGen.init(new X25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

        this.privateKey = (X25519PrivateKeyParameters) keyPair.getPrivate();
        this.publicKey = (X25519PublicKeyParameters) keyPair.getPublic();
    }

    public byte[] getPublicBytes() {
         // returns the public key in raw byte for to be sent to a peer
        return publicKey.getEncoded();
    }

    public byte[] deriveSharedSecret(byte[] peerPublicBytes) {
        /**
         * Combines the local private key with the peer's public key to create a shared secret
         * that is passed through HKDF to derive a secure symmetric key for encrypting messages
         * and files
         */
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(privateKey);

        X25519PublicKeyParameters peerPublicKey = new X25519PublicKeyParameters(peerPublicBytes, 0);
        byte[] rawSecret = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(peerPublicKey, rawSecret, 0);

        // Uses HKDF to service the raw shared secret into a strong AES-256 key for encryption
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(rawSecret, null, "p2p-session".getBytes()));

        this.sharedKey = new byte[32];
        hkdf.generateBytes(sharedKey, 0, 32);
        return sharedKey;
    }

    public byte[] getSharedKey() {
        return sharedKey;
    }

    public byte[] encrypt(byte[] plaintext) throws Exception {
        /**
         * Encrypts the data using AES-256-GCM
         * generates a random 12-byte IV for every message and prepends it
         * to the ciphertext so the receiver can use it for decryption
         */
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sharedKey, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(plaintext);

        // Prepend IV to ciphertext for transmission
        byte[] out = new byte[12 + ct.length];
        System.arraycopy(iv, 0, out, 0,  12);
        System.arraycopy(ct, 0, out, 12, ct.length);
        return out;
    }

    public byte[] decrypt(byte[] blob) throws Exception {
        /**
         * Decrypts the received message
         * pulls the first 12 bytes (the IV) from the blob and then 
         * decrypts the rest of the blob using the shared key
         */
        byte[] iv = new byte[12];
        byte[] ct = new byte[blob.length - 12];
        System.arraycopy(blob, 0,  iv, 0, 12);
        System.arraycopy(blob, 12, ct, 0, ct.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sharedKey, "AES"), new GCMParameterSpec(128, iv));
        return cipher.doFinal(ct);
    }

}