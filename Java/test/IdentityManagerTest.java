import org.junit.Test;
import org.junit.Before;
import org.junit.After;
import static org.junit.Assert.*;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;

public class IdentityManagerTest {

    private IdentityManager identity;
    private final String testUser = "Avery_test_user";
    private final char[] testPassword = "secure_password_123".toCharArray();

    @Before
    public void setUp() throws Exception {
        /**
         * Creates a fresh IdentityManager and generates a new keypair
         * for the test user before each test.
         */
        identity = new IdentityManager(testUser);
        identity.loadOrGenerate(testPassword);
    }

    @After
    public void tearDown() throws Exception {
        /**
         * Deletes the entire test user data directory after each test
         * to ensure a clean slate for the next one.
         */
        Path dir = Paths.get("data_" + testUser);
        if (Files.exists(dir)) {
            Files.walk(dir)
                 .sorted(Comparator.reverseOrder())
                 .map(Path::toFile)
                 .forEach(File::delete);
        }
    }

    @Test
    public void testKeyGenerationAndLoading() throws Exception {
        /**
         * Verifies that a generated keypair can be saved to disk and reloaded,
         * and that the public key is the correct 32-byte size for Ed25519.
         */
        byte[] pubKey = identity.getPublicKeyBytes();
        assertNotNull("Public key should not be null", pubKey);
        assertEquals("Ed25519 public key should be exactly 32 bytes", 32, pubKey.length);

        IdentityManager loadedIdentity = new IdentityManager(testUser);
        loadedIdentity.loadOrGenerate(testPassword);
        byte[] loadedPubKey = loadedIdentity.getPublicKeyBytes();

        assertArrayEquals("Loaded public key should match the generated one", pubKey, loadedPubKey);
    }

    @Test
    public void testValidSignatureVerification() throws Exception {
        /**
         * Verifies that a signature produced by the private key is successfully
         * verified against the corresponding public key.
         */
        byte[] dummyData = "This is a secret handshake message".getBytes("UTF-8");

        byte[] signature = identity.sign(dummyData);

        byte[] myPublicKey = identity.getPublicKeyBytes();
        boolean isValid = identity.verify(myPublicKey, dummyData, signature);

        assertTrue("Signature should be verified successfully", isValid);
    }

    @Test
    public void testInvalidSignatureRejection() throws Exception {
        /**
         * Verifies that a signature produced for one piece of data is rejected
         * when verified against different (tampered) data.
         */
        byte[] originalData = "This is a secret handshake message".getBytes("UTF-8");
        byte[] tamperedData = "This is a HACKED handshake message".getBytes("UTF-8");

        byte[] signature = identity.sign(originalData);

        byte[] myPublicKey = identity.getPublicKeyBytes();
        boolean isValid = identity.verify(myPublicKey, tamperedData, signature);

        assertFalse("Signature verification MUST fail for tampered data", isValid);
    }

    @Test
    public void testKeyMigration() throws Exception {
        /**
         * Verifies that key migration produces a new keypair, and that the new
         * public key is signed by the old private key to prove authorized ownership.
         */
        byte[] oldPubKey = identity.getPublicKeyBytes();

        String[] migrationData = identity.migrateKey(testPassword);

        byte[] newPubKey = java.util.Base64.getDecoder().decode(migrationData[0]);
        byte[] signature = java.util.Base64.getDecoder().decode(migrationData[1]);

        assertFalse("New public key must be different from the old one",
                    java.util.Arrays.equals(oldPubKey, newPubKey));

        boolean isValidLink = identity.verify(oldPubKey, newPubKey, signature);
        assertTrue("The new key must be validly signed by the old key", isValidLink);
    }

    @Test
    public void testLoadWithIncorrectPasswordThrowsException() throws Exception {
        /**
         * Verifies that loading an existing identity with the wrong password
         * throws an exception, preventing unauthorized access to the private key.
         */
        IdentityManager hackerIdentity = new IdentityManager(testUser);
        char[] wrongPassword = "wrong_password_123".toCharArray();
        boolean exceptionThrown = false;

        try {
            hackerIdentity.loadOrGenerate(wrongPassword);
        } catch (Exception e) {
            exceptionThrown = true;
        }

        assertTrue("Loading an identity with the wrong password MUST throw an exception", exceptionThrown);
    }
}