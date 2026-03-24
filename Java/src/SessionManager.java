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

public class SessionManager {

    private X25519PrivateKeyParameters privateKey;
    private X25519PublicKeyParameters publicKey;
    private byte[] sharedKey;

    public SessionManager() {
        X25519KeyPairGenerator keyGen = new X25519KeyPairGenerator();
        keyGen.init(new X25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

        this.privateKey = (X25519PrivateKeyParameters) keyPair.getPrivate();
        this.publicKey = (X25519PublicKeyParameters) keyPair.getPublic();
    }

    public byte[] getPublicBytes() {
        return publicKey.getEncoded();
    }

    public byte[] deriveSharedSecret(byte[] peerPublicBytes) {
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(privateKey);

        X25519PublicKeyParameters peerPublicKey = new X25519PublicKeyParameters(peerPublicBytes, 0);
        byte[] rawSecret = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(peerPublicKey, rawSecret, 0);

        // CHANGED: was "p2p_file_share_session_v1" — must match Python's info=b"p2p-session"
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(rawSecret, null, "p2p-session".getBytes()));

        this.sharedKey = new byte[32];
        hkdf.generateBytes(sharedKey, 0, 32);
        return sharedKey;
    }

    public byte[] getSharedKey() {
        return sharedKey;
    }

    // ADDED: AES-256-GCM encrypt. Wire format: [IV (12B) | ciphertext+tag]
    // Matches Python FileEncryptor.encrypt()
    public byte[] encrypt(byte[] plaintext) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sharedKey, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(plaintext);
        byte[] out = new byte[12 + ct.length];
        System.arraycopy(iv, 0, out, 0,  12);
        System.arraycopy(ct, 0, out, 12, ct.length);
        return out;
    }

    // ADDED: AES-256-GCM decrypt. Expects [IV (12B) | ciphertext+tag]
    // Matches Python FileEncryptor.decrypt()
    public byte[] decrypt(byte[] blob) throws Exception {
        byte[] iv = new byte[12];
        byte[] ct = new byte[blob.length - 12];
        System.arraycopy(blob, 0,  iv, 0, 12);
        System.arraycopy(blob, 12, ct, 0, ct.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sharedKey, "AES"), new GCMParameterSpec(128, iv));
        return cipher.doFinal(ct);
    }

    public static void main(String[] args) {
        SessionManager session = new SessionManager();
        byte[] pubBytes = session.getPublicBytes();
        String pubKeyBase64 = Base64.getEncoder().encodeToString(pubBytes);
        System.out.println("Ephemeral public key (Base64): " + pubKeyBase64);
        System.out.println("Public key size (Base64): " + pubKeyBase64.length() + " characters");
    }
}