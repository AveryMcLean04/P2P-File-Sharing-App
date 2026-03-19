import java.io.*;
import java.net.*;

public class NetworkManager {

    private final int port;
    private ServerSocket serverSocket;

    public NetworkManager(int port) {
        this.port = port;
    }

    public void sendMessage(String address, int port, String jsonMessage) {
        try (Socket socket = new Socket(address, port);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            out.println(jsonMessage);
            System.out.println("[+] Sent to " + address + ":" + port);
        } catch (IOException e) {
            System.out.println("[-] Send failed: " + e.getMessage());
        }
    }

    public void startServer() {
        Thread serverThread = new Thread(() -> {
            try {
                serverSocket = new ServerSocket(port);
                System.out.println("[+] Listening on port " + port);
                while (true) {
                    Socket client = serverSocket.accept();
                    handleConnection(client);
                }
            } catch (IOException e) {
                System.out.println("[-] Server error: " + e.getMessage());
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
    }

    private void handleConnection(Socket client) {
        try (BufferedReader in = new BufferedReader(
                new InputStreamReader(client.getInputStream()))) {
            String line = in.readLine();
            if (line != null) {
                System.out.println("[+] Received: " + line);
            }
        } catch (IOException e) {
            System.out.println("[-] Read error: " + e.getMessage());
        }
    }
}