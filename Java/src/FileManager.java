import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

public class FileManager {
    /**
     * Manages the local file storage, including the encrypted vault,
     * the temporary shared workspace, and the staging area for new files.
     * It handles the encryption and decryption of files using AES-GCM
     * upon initialization and shutdown, as well as when files are received form peers.
     */

    private final String myName;
    private final Path sharedDir;
    private final Path vaultDir;
    private byte[] vaultKey = null;

    private final Path stagingDir;
    private final Path saltFile; 

    public FileManager(String myName) {
        this.myName = myName;
        // dictionary structure for the user's data: 
        this.sharedDir = Paths.get("data_" + myName + "/shared");
        this.vaultDir = Paths.get("data_" + myName + "/vault");
        this.stagingDir = Paths.get("data_" + myName + "/staging");
        this.saltFile = Paths.get("data_" + myName + "/vault.salt"); 
        
        try {
            // if the folders don't exist, create them, if they do, do nothing
            Files.createDirectories(sharedDir);
            Files.createDirectories(vaultDir);
            Files.createDirectories(stagingDir);
        } catch (Exception e) {
            System.out.println("[ERROR] Failed to create directories: " + e.getMessage());
        }
    }

    public void unlockVault(char[] password) {
        /**
         * Uses the user's master password to derive the vault encryption key
         * Once the key is generated, it automatically decrypts all files in the vault into the 
         * shared folder, making them available for peer sharing and local access
         * when the vault is unlocked.
         */
        try {
            byte[] salt;
            // use an existing salt file if available, otherwise create a new one
            if (Files.exists(saltFile)) {
                salt = Files.readAllBytes(saltFile);
            } else {
                salt = new byte[16];
                new SecureRandom().nextBytes(salt);
                Files.write(saltFile, salt);
            }

            // Derive a 256-bit AES key from the password and salt with PBKDF2 wiht 100,000 iterations
            PBEKeySpec spec = new PBEKeySpec(password, salt, 100000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            this.vaultKey = factory.generateSecret(spec).getEncoded();
            
            extractVaultToShared();
        } catch (Exception e) {
            System.out.println("[ERROR] Failed to unlock vault: " + e.getMessage());
        }
    }

    private void extractVaultToShared() {
        /**
         * loops through every encrypted file in the vault, attempts to decrypt it
         * and make a copy in the sared directory
         */
        try (Stream<Path> paths = Files.walk(vaultDir)) {
            paths.filter(Files::isRegularFile).forEach(encryptedFile -> {
                try {
                    byte[] cipherText = Files.readAllBytes(encryptedFile);
                    byte[] plainText = decryptLocalFile(cipherText);

                    String originalName = encryptedFile.getFileName().toString().replace(".enc", "");
                    Files.write(sharedDir.resolve(originalName), plainText);
                    
                } catch (Exception e) {
                    System.out.println("[ERROR] Failed to decrypt '" + encryptedFile.getFileName() + "': Incorrect password or corrupted file.");
                }
            });
            System.out.println("[SYSTEM] Vault unlocked. Files ready in shared folder.");
        } catch (Exception e) {
            System.out.println("[ERROR] Error reading vault directory.");
        }
    }

    public void lockVaultAndCleanup() {
        /**
         * Cleans the workspace by deleting all files in the shared folder
         * and clears the encryption key from memory. This is called when the app is shutdown
         * to ensure that no sensitive data is left on the disk after the vault is locked
         * for secure local storage without the master password.
         */
        System.out.println("[SYSTEM] Securing vault and wiping shared workspace...");
        try (Stream<Path> paths = Files.walk(sharedDir)) {
            paths.sorted(Comparator.reverseOrder())
                 .map(Path::toFile)
                 .filter(f -> !f.getName().equals("shared")) 
                 .forEach(File::delete);
            System.out.println("[SYSTEM] Workspace wiped cleanly.");
        } catch (Exception e) {
            System.out.println("[ERROR] Error wiping workspace: " + e.getMessage());
        }
        // Zero out the vault key in memory
        if (this.vaultKey != null) {
            java.util.Arrays.fill(this.vaultKey, (byte) 0);
        }
    }

    public void saveIncomingFile(String filename, byte[] plainTextData) throws Exception {
        /**
         * Saves an incoming file from a peer into the shared folder for local access, as well as 
         * encrypting a copy into the vault for secure storage.
         */
        Files.write(sharedDir.resolve(filename), plainTextData);
        
        byte[] encryptedData = encryptLocalFile(plainTextData);
        Files.write(vaultDir.resolve(filename + ".enc"), encryptedData);
    }

    public List<String> listSharedFiles() {
        /**
         * Reads the shared directory and returns the list of filenames
         * available to be shared with peers
         */
        List<String> files = new ArrayList<>();
        try (Stream<Path> paths = Files.walk(sharedDir)) {
            paths.filter(Files::isRegularFile)
                 .forEach(path -> files.add(path.getFileName().toString()));
        } catch (Exception e) {
        }
        return files;
    }

    private byte[] encryptLocalFile(byte[] plaintext) throws Exception {
        /**
         * Encrypts a file for local storage in the vault using AES-GCM,
         * prepends the random IV to the ciphertext for later decryption.
         */
        if (vaultKey == null) throw new Exception("Vault is locked!");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        SecretKeySpec keySpec = new SecretKeySpec(vaultKey, "AES");
        
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);
        byte[] cipherText = cipher.doFinal(plaintext);
        
        // Combine IV and ciphertext for storage
        byte[] combined = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);
        return combined;
    }

    private byte[] decryptLocalFile(byte[] combined) throws Exception {
        /**
         * Decrypt a local file by extracting the IV and using the derived vault key
         * to perform AES-GCM decryption, returning the original plaintext
         */
        if (vaultKey == null) throw new Exception("Vault is locked!");
        
        byte[] iv = new byte[12];
        System.arraycopy(combined, 0, iv, 0, 12);
        
        byte[] cipherText = new byte[combined.length - 12];
        System.arraycopy(combined, 12, cipherText, 0, cipherText.length);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        SecretKeySpec keySpec = new SecretKeySpec(vaultKey, "AES");
        
        cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);
        return cipher.doFinal(cipherText);
    }


    public void importFromStaging() {
        /**
         * Checks the staging directory for any new files added by the user,
         * if it is not empty, it imports them into the secure vault folder,
         * and makes a copy in the shared folder for immediate local access and sharing ability,
         * the original is deleted from the staging area after successful import.
         */
        System.out.println("[SYSTEM] Checking staging area for files...");
        try (Stream<Path> paths = Files.walk(stagingDir)) {
            java.util.List<Path> filesToImport = paths.filter(Files::isRegularFile)
                                                      .collect(java.util.stream.Collectors.toList());

            if (filesToImport.isEmpty()) {
                System.out.println("[SYSTEM] Staging area is empty. Drop files into 'data_" + myName + "/staging' first.");
                return;
            }

            for (Path file : filesToImport) {
                String fileName = file.getFileName().toString();
                byte[] fileData = Files.readAllBytes(file);

                saveIncomingFile(fileName, fileData);

                // cleans up the staging directory after importing
                Files.delete(file);
                System.out.println("[FILE] Secured and imported: " + fileName);
            }
            System.out.println("[SYSTEM] Import complete. Staging area is now clean.");

        } catch (Exception e) {
            System.out.println("[ERROR] Error during import: " + e.getMessage());
        }
    }
}