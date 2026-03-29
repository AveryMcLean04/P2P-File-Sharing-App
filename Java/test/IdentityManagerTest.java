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
        // This runs before every test to ensure a clean slate
        identity = new IdentityManager(testUser);
        identity.loadOrGenerate(testPassword);
    }

    @After
    public void tearDown() throws Exception {
        // Clean up the test files after tests run so we don't clutter your drive
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
        // 1. Verify that the public key is not null and has the correct Ed25519 length (32 bytes)
        byte[] pubKey = identity.getPublicKeyBytes();
        assertNotNull("Public key should not be null", pubKey);
        assertEquals("Ed25519 public key should be exactly 32 bytes", 32, pubKey.length);

        // 2. Test that loading the existing keys works with the correct password
        IdentityManager loadedIdentity = new IdentityManager(testUser);
        loadedIdentity.loadOrGenerate(testPassword);
        byte[] loadedPubKey = loadedIdentity.getPublicKeyBytes();
        
        assertArrayEquals("Loaded public key should match the generated one", pubKey, loadedPubKey);
    }

    @Test
    public void testValidSignatureVerification() throws Exception {
        byte[] dummyData = "This is a secret handshake message".getBytes("UTF-8");

        // 1. Sign the data
        byte[] signature = identity.sign(dummyData);

        // 2. Verify the signature using the public key
        byte[] myPublicKey = identity.getPublicKeyBytes();
        boolean isValid = identity.verify(myPublicKey, dummyData, signature);

        assertTrue("Signature should be verified successfully", isValid);
    }

    @Test
    public void testInvalidSignatureRejection() throws Exception {
        byte[] originalData = "This is a secret handshake message".getBytes("UTF-8");
        byte[] tamperedData = "This is a HACKED handshake message".getBytes("UTF-8");

        // 1. Sign the original data
        byte[] signature = identity.sign(originalData);

        // 2. Attempt to verify the signature against the TAMPERED data
        byte[] myPublicKey = identity.getPublicKeyBytes();
        boolean isValid = identity.verify(myPublicKey, tamperedData, signature);

        assertFalse("Signature verification MUST fail for tampered data", isValid);
    }
}