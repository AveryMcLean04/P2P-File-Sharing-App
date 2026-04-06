import org.junit.Test;
import static org.junit.Assert.*;

public class SessionManagerTest {

    @Test
    public void testSharedSecretDerivation() throws Exception {
        /**
         * Verifies that two peers performing an X25519 key exchange independently
         * arrive at the exact same shared secret.
         */
        SessionManager aliceSession = new SessionManager();
        SessionManager bobSession = new SessionManager();

        byte[] aliceSecret = aliceSession.deriveSharedSecret(bobSession.getPublicBytes());
        byte[] bobSecret = bobSession.deriveSharedSecret(aliceSession.getPublicBytes());

        assertNotNull("Alice's secret should not be null", aliceSecret);
        assertNotNull("Bob's secret should not be null", bobSecret);
        assertArrayEquals("Both derived shared secrets MUST be identical", aliceSecret, bobSecret);
    }

    @Test
    public void testEncryptionAndDecryption() throws Exception {
        /**
         * Verifies that a message encrypted by one peer can be successfully
         * decrypted by the other peer using their shared session key.
         */
        SessionManager aliceSession = new SessionManager();
        SessionManager bobSession = new SessionManager();

        aliceSession.deriveSharedSecret(bobSession.getPublicBytes());
        bobSession.deriveSharedSecret(aliceSession.getPublicBytes());

        String originalMessage = "Top Secret P2P File Data";
        byte[] encryptedData = aliceSession.encrypt(originalMessage.getBytes("UTF-8"));

        byte[] decryptedData = bobSession.decrypt(encryptedData);
        String decryptedMessage = new String(decryptedData, "UTF-8");

        assertEquals("Decrypted message should match the original", originalMessage, decryptedMessage);
    }

    @Test
    public void testTamperedDataRejection() throws Exception {
        /**
         * Verifies that AES-GCM authentication catches any tampering with the
         * ciphertext by throwing an AEADBadTagException on decryption.
         */
        SessionManager aliceSession = new SessionManager();
        SessionManager bobSession = new SessionManager();

        aliceSession.deriveSharedSecret(bobSession.getPublicBytes());
        bobSession.deriveSharedSecret(aliceSession.getPublicBytes());

        byte[] encryptedData = aliceSession.encrypt("Sensitive Information".getBytes("UTF-8"));

        // flip the last bit to simulate in-transit tampering
        encryptedData[encryptedData.length - 1] ^= 1;

        boolean exceptionThrown = false;
        try {
            bobSession.decrypt(encryptedData);
        } catch (javax.crypto.AEADBadTagException e) {
            exceptionThrown = true;
        }

        assertTrue("An AEADBadTagException MUST be thrown when decrypting tampered data", exceptionThrown);
    }

    @Test
    public void testIvRandomness() throws Exception {
        /**
         * Verifies that encrypting the same plaintext twice produces different
         * ciphertexts, confirming that a fresh random IV is used each time.
         */
        SessionManager aliceSession = new SessionManager();
        SessionManager bobSession = new SessionManager();
        aliceSession.deriveSharedSecret(bobSession.getPublicBytes());

        byte[] plainText = "message".getBytes("UTF-8");

        byte[] cipherText1 = aliceSession.encrypt(plainText);
        byte[] cipherText2 = aliceSession.encrypt(plainText);

        assertFalse("Ciphertexts should differ due to random IVs", java.util.Arrays.equals(cipherText1, cipherText2));
    }
}