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

public class IdentityManager {

    private final String pubKeyFile;
    private final String privKeyFile;

    public IdentityManager(String username) {
        //create a directory for the user if it doesn't exist yet
        java.io.File userDir = new java.io.File("data_" + username);
        if (!userDir.exists()) {
            userDir.mkdirs();
        }

        //set the paths
        this.pubKeyFile = "data_" + username + "/identity.pub";
        this.privKeyFile = "data_" + username + "/identity.key";
    }

    // PBKDF2 parameters
    private static final int PBKDF2_ITERATIONS = 200_000;
    private static final int PBKDF2_KEY_LENGTH  = 256; // bits
    private static final int SALT_SIZE          = 16;  // bytes

    // AES-GCM parameters
    private static final int NONCE_SIZE = 12; // bytes
    private static final int GCM_TAG_LENGTH = 128; // bits

    private Ed25519PrivateKeyParameters privateKey;
    private Ed25519PublicKeyParameters  publicKey;

    public void loadOrGenerate(char[] password) throws Exception {
        if (keyFilesExist()) {
            loadKeys(password);
        } else {
            generateAndSave(password);
        }
    }

    private boolean keyFilesExist() {
        return Files.exists(Paths.get(privKeyFile)) &&
               Files.exists(Paths.get(pubKeyFile));
    }

    private void generateAndSave(char[] password) throws Exception {
        System.out.println("[SECURITY] No identity found. Generating new keys...");

        Ed25519KeyPairGenerator keyGen = new Ed25519KeyPairGenerator();
        keyGen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = keyGen.generateKeyPair();

        this.privateKey = (Ed25519PrivateKeyParameters) keyPair.getPrivate();
        this.publicKey = (Ed25519PublicKeyParameters) keyPair.getPublic();

        saveKeys(password);

        System.out.println("[SECURITY] Identity keypair generated and saved.");
    }

    private void loadKeys(char[] password) throws Exception {
        byte[] pubKeyBytes = Files.readAllBytes(Paths.get(pubKeyFile));
        this.publicKey = new Ed25519PublicKeyParameters(pubKeyBytes, 0);

        byte[] encryptedPrivKey = Files.readAllBytes(Paths.get(privKeyFile));
        byte[] privKeyBytes = decryptPrivateKey(encryptedPrivKey, password);
        this.privateKey = new Ed25519PrivateKeyParameters(privKeyBytes, 0);

        printFingerprint();
    }

    private byte[] encryptPrivateKey(byte[] rawPrivKey, char[] password) throws Exception {
        SecureRandom rng = new SecureRandom();

        byte[] salt = new byte[SALT_SIZE];
        rng.nextBytes(salt);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
        byte[] aesKeyBytes = factory.generateSecret(spec).getEncoded();
        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        byte[] nonce = new byte[NONCE_SIZE];
        rng.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
        byte[] ciphertext = cipher.doFinal(rawPrivKey);

        byte[] results = new byte[salt.length + nonce.length + ciphertext.length];
        System.arraycopy(salt, 0, results, 0, salt.length);
        System.arraycopy(nonce, 0, results, salt.length, nonce.length);
        System.arraycopy(ciphertext, 0, results, salt.length + nonce.length, ciphertext.length);
        return results;
    }

    private byte[] decryptPrivateKey(byte[] stored, char[] password) throws Exception {
        byte[] salt = Arrays.copyOfRange(stored, 0, SALT_SIZE);
        byte[] nonce = Arrays.copyOfRange(stored, SALT_SIZE, SALT_SIZE + NONCE_SIZE);
        byte[] ciphertext = Arrays.copyOfRange(stored, SALT_SIZE + NONCE_SIZE, stored.length);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
        byte[] aesKeyBytes = factory.generateSecret(spec).getEncoded();
        SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
        return cipher.doFinal(ciphertext);
    }

    public byte[] sign(byte[] data) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(data, 0, data.length);
        return signer.generateSignature();
    }

    public boolean verify(byte[] peerPublicKeyBytes, byte[] data, byte[] signature) {
        Ed25519PublicKeyParameters peerPubKey = new Ed25519PublicKeyParameters(peerPublicKeyBytes, 0);
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, peerPubKey);
        verifier.update(data, 0, data.length);
        return verifier.verifySignature(signature);
    }

    public byte[] getPublicKeyBytes() {
        return publicKey.getEncoded();
    }

    public void printFingerprint() {
        SHA256Digest digest = new SHA256Digest();
        byte[] fingerprint = new byte[digest.getDigestSize()];
        digest.update(getPublicKeyBytes(), 0, getPublicKeyBytes().length);
        digest.doFinal(fingerprint, 0);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < fingerprint.length; i++) {
            sb.append(String.format("%02X", fingerprint[i]));
        }
        System.out.println("[SECURITY] Identity Verified: [ID: " + sb.toString().substring(0, 12).toLowerCase() + "...]");
    }

    private void saveKeys(char[] password) throws Exception {
        Files.write(Paths.get(pubKeyFile), publicKey.getEncoded());

        byte[] encryptedPrivKey = encryptPrivateKey(privateKey.getEncoded(), password);
        Files.write(Paths.get(privKeyFile), encryptedPrivKey);
        
        printFingerprint();
    }
    
    public String[] migrateKey(char[] password) throws Exception {
        System.out.println("[SECURITY] Generating new Identity Keypair for migration...");

        org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator keyGen = new org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator();
        keyGen.init(new org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(new java.security.SecureRandom()));
        org.bouncycastle.crypto.AsymmetricCipherKeyPair newKeyPair = keyGen.generateKeyPair();

        org.bouncycastle.crypto.params.Ed25519PublicKeyParameters newPubKey = (org.bouncycastle.crypto.params.Ed25519PublicKeyParameters) newKeyPair.getPublic();
        org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters newPrivKey = (org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters) newKeyPair.getPrivate();

        byte[] newPubKeyBytes = newPubKey.getEncoded();

        byte[] signature = this.sign(newPubKeyBytes);

        this.publicKey = newPubKey;
        this.privateKey = newPrivKey;

        this.saveKeys(password); 

        String newKeyB64 = java.util.Base64.getEncoder().encodeToString(newPubKeyBytes);
        String sigB64 = java.util.Base64.getEncoder().encodeToString(signature);

        System.out.println("[SECURITY] Identity migrated. Old key invalidated.");
        
        return new String[]{newKeyB64, sigB64};
    }
}