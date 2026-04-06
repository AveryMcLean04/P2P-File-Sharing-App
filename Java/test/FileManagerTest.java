import org.junit.Test;
import org.junit.Before;
import org.junit.After;
import static org.junit.Assert.*;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.List;

public class FileManagerTest {

    private FileManager fileManager;
    private final String testUser = "Avery_test";
    private final char[] testPassword = "Avery_test_password".toCharArray();

    private Path shared;
    private Path vault;
    private Path staging;

    @Before
    public void setup() throws Exception {
        /**
         * Creates a fresh FileManager instance and resolves the paths
         * for the shared, vault, and staging directories before each test.
         */
        fileManager = new FileManager(testUser);

        shared = Paths.get("data_" + testUser, "shared");
        vault = Paths.get("data_" + testUser, "vault");
        staging = Paths.get("data_" + testUser, "staging");
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
    public void testLockVaultAndCleanup() throws Exception {
        /**
         * Verifies that locking the vault removes all plaintext files from the
         * shared folder while keeping the encrypted copies in the vault.
         */
        fileManager.unlockVault(testPassword);
        String testFile = "temp.txt";
        fileManager.saveIncomingFile(testFile, "Temporary file".getBytes("UTF-8"));

        assertTrue(Files.exists(shared.resolve(testFile)));

        fileManager.lockVaultAndCleanup();

        assertFalse("File should be deleted from shared after locking the vault", Files.exists(shared.resolve(testFile)));
        assertTrue("File should still be in the vault", Files.exists(vault.resolve(testFile + ".enc")));
    }

    @Test
    public void testImportFromStaging() throws Exception {
        /**
         * Verifies that a file placed in the staging directory gets moved into
         * both the shared folder and the encrypted vault, and is removed from staging.
         */
        fileManager.unlockVault(testPassword);

        String testFile2 = "temp2.txt";
        Path stagingPath = staging.resolve(testFile2);
        Files.write(stagingPath, "Staging file".getBytes("UTF-8"));

        fileManager.importFromStaging();

        assertFalse("File should not be in staging directory after importing", Files.exists(stagingPath));
        assertTrue("File should now be in shared", Files.exists(shared.resolve(testFile2)));
        assertTrue("File should now be encrypted in vault", Files.exists(vault.resolve(testFile2 + ".enc")));
    }

    @Test
    public void testSaveWithoutUnlocking() throws Exception {
        /**
         * Verifies that attempting to save a file without first unlocking the vault
         * throws an exception, preventing writes to a locked vault.
         */
        String testFile3 = "temp3.txt";
        boolean exception = false;

        try {
            fileManager.saveIncomingFile(testFile3, "Should fail".getBytes("UTF-8"));
        } catch (Exception e) {
            exception = true;
            assertTrue("Expected an exception when trying to save without unlocking the vault", e.getMessage().contains("locked"));
        }

        assertTrue("An exception MUST be thrown", exception);
    }

    @Test
    public void testUnlockWithWrongPassword() throws Exception {
        /**
         * Verifies that a file encrypted with the correct password cannot be
         * decrypted when an incorrect password is used to unlock the vault.
         */
        fileManager.unlockVault(testPassword);
        String testFile4 = "temp4.txt";
        fileManager.saveIncomingFile(testFile4, "Regular file".getBytes("UTF-8"));

        fileManager.lockVaultAndCleanup();

        assertTrue("Encrypted file should exist in the vault", Files.exists(vault.resolve(testFile4 + ".enc")));
        assertFalse("Plaintext files should be wiped after locking the vault", Files.exists(shared.resolve(testFile4)));

        char[] wrongPassword = "wrongPassword".toCharArray();
        fileManager.unlockVault(wrongPassword);

        assertFalse("File should not be decrypted with wrong password", Files.exists(shared.resolve(testFile4)));
        assertTrue("Encrypted file should still exist in the vault", Files.exists(vault.resolve(testFile4 + ".enc")));
    }

    @Test
    public void testCorruptedFileHandling() throws Exception {
        /**
         * Verifies that a file whose encrypted bytes have been tampered with
         * cannot be decrypted, and does not appear in the shared folder.
         */
        fileManager.unlockVault(testPassword);
        String testFile5 = "temp5.txt";
        fileManager.saveIncomingFile(testFile5, "This file will be corrupted".getBytes("UTF-8"));
        fileManager.lockVaultAndCleanup();

        // flip one bit in the encrypted file to simulate tampering
        Path encryptedFilePath = vault.resolve(testFile5 + ".enc");
        byte[] encryptedData = Files.readAllBytes(encryptedFilePath);
        encryptedData[0] ^= 1;
        Files.write(encryptedFilePath, encryptedData);

        fileManager.unlockVault(testPassword);

        assertFalse("Corrupted file should not have been decrypted", Files.exists(shared.resolve(testFile5)));
    }
}