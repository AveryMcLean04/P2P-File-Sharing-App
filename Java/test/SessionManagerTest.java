import org.junit.Test;
import static org.junit.Assert.*;

public class SessionManagerTest {

    @Test
    public void testSharedSecretDerivation() throws Exception {
        // Create two separate sessions (representing Alice and Bob)
        SessionManager aliceSession = new SessionManager();
        SessionManager bobSession = new SessionManager();

        // Exchange public keys and derive shared secrets (Requirement 8)
        byte[] aliceSecret = aliceSession.deriveSharedSecret(bobSession.getPublicBytes());
        byte[] bobSecret = bobSession.deriveSharedSecret(aliceSession.getPublicBytes());

        // Assert that both parties arrived at the exact same 32-byte AES key
        assertNotNull("Alice's secret should not be null", aliceSecret);
        assertNotNull("Bob's secret should not be null", bobSecret);
        assertArrayEquals("Both derived shared secrets MUST be identical", aliceSecret, bobSecret);
    }

    @Test
    public void testEncryptionAndDecryption() throws Exception {
        SessionManager aliceSession = new SessionManager();
        SessionManager bobSession = new SessionManager();

        // Establish the secure tunnel
        aliceSession.deriveSharedSecret(bobSession.getPublicBytes());
        bobSession.deriveSharedSecret(aliceSession.getPublicBytes());

        // Alice encrypts a message
        String originalMessage = "Top Secret P2P File Data";
        byte[] encryptedData = aliceSession.encrypt(originalMessage.getBytes("UTF-8"));

        // Bob decrypts the message (Requirement 7)
        byte[] decryptedData = bobSession.decrypt(encryptedData);
        String decryptedMessage = new String(decryptedData, "UTF-8");

        // Assert that the message survived the round trip perfectly
        assertEquals("Decrypted message should match the original", originalMessage, decryptedMessage);
    }

    // The (expected = ...) tells JUnit that this test ONLY passes if the specific exception is thrown!
    @Test(expected = javax.crypto.AEADBadTagException.class)
    public void testTamperedDataRejection() throws Exception {
        SessionManager aliceSession = new SessionManager();
        SessionManager bobSession = new SessionManager();

        aliceSession.deriveSharedSecret(bobSession.getPublicBytes());
        bobSession.deriveSharedSecret(aliceSession.getPublicBytes());

        byte[] encryptedData = aliceSession.encrypt("Sensitive Information".getBytes("UTF-8"));

        // THE ATTACK: A hacker intercepts the data and flips a single byte
        encryptedData[encryptedData.length - 1] ^= 1; 

        // Bob tries to decrypt the tampered data. 
        // We expect AES-GCM to catch this and throw the AEADBadTagException (Requirement 10)
        bobSession.decrypt(encryptedData);
    }
}