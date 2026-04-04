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
        fileManager = new FileManager(testUser); // Fixed capitalization

        shared = Paths.get("data_" + testUser, "shared");
        vault = Paths.get("data_" + testUser, "vault");
        staging = Paths.get("data_" + testUser, "staging");
    }

    @After
    public void tearDown() throws Exception {
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
        fileManager.unlockVault(testPassword);

        String testFile2 = "temp2.txt";
        Path stagingPath = staging.resolve(testFile2);
        Files.write(stagingPath, "Staging file".getBytes("UTF-8"));

        fileManager.importFromStaging(); // Fixed capitalization

        assertFalse("File should not be in staging directory after importing", Files.exists(stagingPath));
        assertTrue("File should now be in shared", Files.exists(shared.resolve(testFile2))); // Replaced undefined variables
        assertTrue("File should now be encrypted in vault", Files.exists(vault.resolve(testFile2 + ".enc"))); // Replaced undefined variables
    }

    @Test
    public void testSaveWithoutUnlocking() throws Exception {
        // fileManager.unlockVault(testPassword); intentionally not unlocking the vault to fail (Fixed typo)

        String testFile3 = "temp3.txt";
        boolean exception = false;

        try {
            fileManager.saveIncomingFile(testFile3, "Should fail".getBytes("UTF-8")); // Fixed typo
        } catch (Exception e) {
            exception = true;
            assertTrue("Expected an exception when trying to save without unlocking the vault", e.getMessage().contains("locked"));
        }
        
        assertTrue("An exception MUST be thrown", exception); // Added this so the test actually fails if no exception is thrown
    }

    @Test
    public void testUnlockWithWrongPassword() throws Exception {
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
        fileManager.unlockVault(testPassword);
        String testFile5 = "temp5.txt";
        fileManager.saveIncomingFile(testFile5, "This file will be corrupted".getBytes("UTF-8"));
        fileManager.lockVaultAndCleanup();

        //flipping one bit
        Path encryptedFilePath = vault.resolve(testFile5 + ".enc");
        byte[] encryptedData = Files.readAllBytes(encryptedFilePath);
        encryptedData[0] ^= 1;
        Files.write(encryptedFilePath, encryptedData);

        fileManager.unlockVault(testPassword);

        assertFalse("Corrupted file should not have been decrypted", Files.exists(shared.resolve(testFile5)));
    }
}