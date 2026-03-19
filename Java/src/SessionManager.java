import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
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
        // Step 1: ECDH exchange
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(privateKey);

        X25519PublicKeyParameters peerPublicKey = new X25519PublicKeyParameters(peerPublicBytes, 0);
        byte[] rawSecret = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(peerPublicKey, rawSecret, 0);

        // Step 2: HKDF with SHA-256 — matches Python's HKDF(SHA256, length=32, info=b"p2p_file_share_session_v1")
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(rawSecret, null, "p2p_file_share_session_v1".getBytes()));

        this.sharedKey = new byte[32];
        hkdf.generateBytes(sharedKey, 0, 32);

        return sharedKey;
    }

    public byte[] getSharedKey() {
        return sharedKey;
    }

    public static void main(String[] args) {
        SessionManager session = new SessionManager();
        byte[] pubBytes = session.getPublicBytes();
        String pubKeyBase64 = Base64.getEncoder().encodeToString(pubBytes);
        System.out.println("Ephemeral public key (Base64): " + pubKeyBase64);
        System.out.println("Public key size (Base64): " + pubKeyBase64.length() + " characters");
    }
}