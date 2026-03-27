import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class FileManager {
    private final String sharedDir;
    private final String downloadsDir;

    public FileManager(String username) {
        // Define the paths
        this.sharedDir = "data_" + username + "/shared";
        this.downloadsDir = "data_" + username + "/downloads";

        // Create the folders if they don't exist
        new File(sharedDir).mkdirs();
        new File(downloadsDir).mkdirs();
    }

    /**
     * Scans the user's /shared directory and returns a list of filenames.
     */
    public List<String> listSharedFiles() {
        List<String> fileNames = new ArrayList<>();
        File folder = new File(sharedDir);
        File[] listOfFiles = folder.listFiles();

        if (listOfFiles != null) {
            for (File file : listOfFiles) {
                if (file.isFile()) {
                    fileNames.add(file.getName());
                }
            }
        }
        return fileNames;
    }
}