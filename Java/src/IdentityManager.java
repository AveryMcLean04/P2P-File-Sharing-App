import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Manages the long-term Ed25519 identity keypair for this peer.
 *
 * Responsibilities:
 *  - Generate a new keypair on first run
 *  - Encrypt the private key with a user password (PBKDF2 + AES-GCM)
 *  - Save/load the encrypted private key and public key to disk
 *  - Sign data (used during the handshake to authenticate ephemeral keys)
 *  - Verify signatures from other peers
 *
 * File layout on disk:
 *  identity.pub  — raw 32-byte Ed25519 public key (not secret, can be shared)
 *  identity.key  — encrypted private key: [ salt (16B) | nonce (12B) | ciphertext (32B+tag) ]
 */
public class IdentityManager {

    private static final String PUB_KEY_FILE  = "identity.pub";
    private static final String PRIV_KEY_FILE = "identity.key";

    // PBKDF2 parameters — tune ITERATIONS for your security/performance tradeoff
    private static final int PBKDF2_ITERATIONS = 200_000;
    private static final int PBKDF2_KEY_LENGTH  = 256; // bits
    private static final int SALT_SIZE          = 16;  // bytes

    // AES-GCM parameters
    private static final int NONCE_SIZE = 12; // bytes (96-bit nonce recommended for GCM)
    private static final int GCM_TAG_LENGTH = 128; // bits

    private Ed25519PrivateKeyParameters privateKey;
    private Ed25519PublicKeyParameters  publicKey;

    // -------------------------------------------------------------------------
    // Initialisation: load existing keys or generate new ones
    // -------------------------------------------------------------------------

    /**
     * Load keys from disk, prompting the user for their password.
     * If no key files exist, generates a new keypair and saves it.
     *
     * @param password the user's password (char[] so it can be zeroed after use)
     */
    public void loadOrGenerate(char[] password) throws Exception {
        if (keyFilesExist()) {
            loadKeys(password);
        } else {
            generateAndSave(password);
        }
    }

    private boolean keyFilesExist() {
        return Files.exists(Paths.get(PRIV_KEY_FILE)) &&
               Files.exists(Paths.get(PUB_KEY_FILE));
    }

    // -------------------------------------------------------------------------
    // Key generation
    // -------------------------------------------------------------------------

    /**
     * Generate a new Ed25519 keypair, save public key to disk in plaintext,
     * and save private key to disk encrypted with the given password.
     */
    private void generateAndSave(char[] password) throws Exception {
        System.out.println("[*] No identity keys found. Generating new Ed25519 keypair...");

        Ed25519KeyPairGenerator keyGen = new Ed25519KeyPairGenerator();
        keyGen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

        this.privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
        this.publicKey = (Ed25519PublicKeyParameters) keyPair.getPublic();

        Files.write(Paths.get(PUB_KEY_FILE), publicKey.getEncoded());

        byte[] encryptedPrivKey = encryptPrivateKey(privateKey.getEncoded(), password);
        Files.write(Paths.get(PRIV_KEY_FILE), encryptedPrivKey);

        System.out.println("[+] Identity keypair generated and saved.");
        printFingerprint();
}

    // -------------------------------------------------------------------------
    // Key loading
    // -------------------------------------------------------------------------

    /**
     * Load and decrypt keys from disk.
     */
    private void loadKeys(char[] password) throws Exception {
        // Load public key (just raw bytes, no encryption)
        byte[] pubKeyBytes = Files.readAllBytes(Paths.get(PUB_KEY_FILE));
        this.publicKey = new Ed25519PublicKeyParameters(pubKeyBytes, 0);

        // Load and decrypt private key
        byte[] encryptedPrivKey = Files.readAllBytes(Paths.get(PRIV_KEY_FILE));
        byte[] privKeyBytes = decryptPrivateKey(encryptedPrivKey, password);
        this.privateKey = new Ed25519PrivateKeyParameters(privKeyBytes, 0);

        System.out.println("[+] Identity keys loaded.");
        printFingerprint();
    }

    // -------------------------------------------------------------------------
    // Encryption / Decryption of the private key at rest (req 9)
    // -------------------------------------------------------------------------

    /**
     * Encrypt rawPrivKey using AES-GCM with a key derived from password via PBKDF2.
     * Returns: [ salt (16B) | nonce (12B) | ciphertext+tag ]
     */
    private byte[] encryptPrivateKey(byte[] rawPrivKey, char[] password) throws Exception {
        SecureRandom rng = new SecureRandom();

        // 1. Generate a random salt for PBKDF2
        byte[] salt = new byte[SALT_SIZE];
        rng.nextBytes(salt);

        // 2. Derive AES key from password using PBKDF2-HMAC-SHA256
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
        byte[] aesKeyBytes = factory.generateSecret(spec).getEncoded();
        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // 3. Generate a random nonce for AES-GCM
        byte[] nonce = new byte[NONCE_SIZE];
        rng.nextBytes(nonce);

        // 4. Encrypt with AES-GCM
        // TODO: Cipher.getInstance("AES/GCM/NoPadding"), init with ENCRYPT_MODE,
        //       SecretKeySpec (AES), GCMParameterSpec(GCM_TAG_LENGTH, nonce)
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
        byte[] ciphertext = cipher.doFinal(rawPrivKey);

        // 5. Concatenate salt | nonce | ciphertext and return
        // TODO: return concatenated bytes
        byte[] results = new byte[salt.length + nonce.length + ciphertext.length];
        System.arraycopy(salt, 0, results, 0, salt.length);
        System.arraycopy(nonce, 0, results, salt.length, nonce.length);
        System.arraycopy(ciphertext, 0, results, salt.length + nonce.length, ciphertext.length);
        return results;
    }

    /**
     * Reverse of encryptPrivateKey — parses salt/nonce/ciphertext and decrypts.
     */
    private byte[] decryptPrivateKey(byte[] stored, char[] password) throws Exception {
        // 1. Parse: salt (first 16B), nonce (next 12B), ciphertext (rest)
        byte[] salt = Arrays.copyOfRange(stored, 0, SALT_SIZE);
        byte[] nonce = Arrays.copyOfRange(stored, SALT_SIZE, SALT_SIZE + NONCE_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(stored, SALT_SIZE + NONCE_SIZE, stored.length);

        // 2. Re-derive AES key from password + salt (same params as encryption)
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
        byte[] aesKeyBytes = factory.generateSecret(spec).getEncoded();
        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        // 3. Decrypt with AES-GCM (GCM will throw if the tag doesn't verify —
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
        byte[] plaintext = cipher.doFinal(ciphertext);

        return plaintext;
    }

    // -------------------------------------------------------------------------
    // Signing and verification (used in the handshake)
    // -------------------------------------------------------------------------

    /**
     * Sign data with this peer's Ed25519 private key.
     * During the handshake, you'll sign your ephemeral X25519 public key bytes.
     *
     * @param data the bytes to sign (e.g. ephemeral public key)
     * @return 64-byte Ed25519 signature
     */
    public byte[] sign(byte[] data) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(data, 0, data.length);
        return signer.generateSignature();
    }

    /**
     * Verify a signature from a peer using their Ed25519 public key.
     *
     * @param peerPublicKeyBytes the peer's raw 32-byte Ed25519 public key
     * @param data               the data that was signed
     * @param signature          the 64-byte signature to verify
     * @return true if valid, false otherwise
     */
    public boolean verify(byte[] peerPublicKeyBytes, byte[] data, byte[] signature) {
        // TODO: construct Ed25519PublicKeyParameters from peerPublicKeyBytes,
        //       use Ed25519Signer in verify mode
        Ed25519PublicKeyParameters peerPubKey = new Ed25519PublicKeyParameters(peerPublicKeyBytes, 0);
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, peerPubKey);
        verifier.update(data, 0, data.length);
        return verifier.verifySignature(signature);
    }

    // -------------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------------

    public byte[] getPublicKeyBytes() {
        return publicKey.getEncoded();
    }

    /**
     * Print a short fingerprint of the public key so users can verify
     * each other's identity out-of-band (e.g. over the phone).
     * A common approach: hex-encode the first 20 bytes of SHA-256(pubkey),
     * formatted in groups like: A1:B2:C3:...
     */
    public void printFingerprint() {
        SHA256Digest digest = new SHA256Digest();
        byte[] fingerprint = new byte[digest.getDigestSize()];
        digest.update(getPublicKeyBytes(), 0, getPublicKeyBytes().length);
        digest.doFinal(fingerprint, 0);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            sb.append(String.format("%02X", fingerprint[i]));
            if (i < 19) sb.append(":");
        }
        System.out.println("[*] Fingerprint: " + sb.toString());
    }
}