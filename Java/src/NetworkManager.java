import java.io.*;
import java.net.*;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class NetworkManager {

    private final int port;
    private ServerSocket serverSocket;
    private final IdentityManager identity;
    private final String myName;
    private MessageDispatcher dispatcher;

    private final Map<String, SessionManager> pendingSessions = new ConcurrentHashMap<>();
    // CHANGED: stores SessionManager instead of raw byte[] so callers can encrypt/decrypt
    private final Map<String, SessionManager> sessions = new ConcurrentHashMap<>();

    public NetworkManager(int port, IdentityManager identity, String myName) {
        this.port     = port;
        this.identity = identity;
        this.myName   = myName;
    }

    public void setDispatcher(MessageDispatcher dispatcher) {
        this.dispatcher = dispatcher;
    }

    public void startServer() {
        Thread serverThread = new Thread(() -> {
            try {
                serverSocket = new ServerSocket(port);
                System.out.println("[+] Listening on port " + port);
                while (true) {
                    Socket client = serverSocket.accept();
                    new Thread(() -> handleConnection(client)).start();
                }
            } catch (IOException e) {
                System.out.println("[-] Server error: " + e.getMessage());
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
    }

    // CHANGED: was readLine() — Python sends no trailing newline so readLine() blocked forever.
    // Now reads until the remote closes the connection, matching Python's _handle_client exactly.
    private void handleConnection(Socket client) {
        try (client) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            InputStream in = client.getInputStream();
            byte[] chunk = new byte[4096];
            int n;
            while ((n = in.read(chunk)) != -1) {
                buffer.write(chunk, 0, n);
            }
            String message = buffer.toString("UTF-8").trim();
            if (!message.isEmpty()) {
                dispatcher.handle(message);
            }
        } catch (IOException e) {
            System.out.println("[-] Connection error: " + e.getMessage());
        }
    }

    public void sendMessage(String address, int port, String jsonMessage) {
        try (Socket socket = new Socket(address, port)) {
            byte[] data = (jsonMessage + "\n").getBytes("UTF-8");
            socket.getOutputStream().write(data);
            socket.getOutputStream().flush();
            socket.shutdownOutput(); 
        } catch (IOException e) {
            System.out.println("[-] Send failed to " + address + ":" + port + " — " + e.getMessage());
        }
    }

    public void connectToPeer(String address, int port, String peerName) {
        try {
            SessionManager session = new SessionManager();
            pendingSessions.put(peerName, session);

            byte[] myEphemeralRaw = session.getPublicBytes();
            byte[] mySignature    = identity.sign(myEphemeralRaw);
            byte[] myIdentityPub  = identity.getPublicKeyBytes();

            // CHANGED: field names now match Python's initiate_handshake() exactly:
            // "identity_key" and "ephemeral_share" (not "ephemeral_key")
            String initMsg = "{\"type\":\"HANDSHAKE_INIT\"," +
                             "\"sender\":\"" + myName + "\"," +
                             "\"payload\":{" +
                             "\"identity_key\":\""    + Base64.getEncoder().encodeToString(myIdentityPub)  + "\"," +
                             "\"ephemeral_share\":\"" + Base64.getEncoder().encodeToString(myEphemeralRaw) + "\"," +
                             "\"signature\":\""       + Base64.getEncoder().encodeToString(mySignature)    + "\"," +
                             "\"timestamp\":"         + (System.currentTimeMillis() / 1000L) +
                             "}}";

            sendMessage(address, port, initMsg);
            System.out.println("[*] HANDSHAKE_INIT sent to " + peerName + ". Waiting for response...");

        } catch (Exception e) {
            System.out.println("[-] Connect failed: " + e.getMessage());
            pendingSessions.remove(peerName);
        }
    }

    // ADDED: broadcast PEER_LEFT to all known peers on shutdown, matches Python's broadcast_peer_left()
    public void broadcastPeerLeft(String senderId, Map<String, String[]> peers) {
        String msg = "{\"type\":\"PEER_LEFT\",\"sender\":\"" + senderId + "\",\"payload\":{}}";
        for (String[] info : peers.values()) {
            if (info != null && info[0] != null && info[1] != null) {
                sendMessage(info[0], Integer.parseInt(info[1]), msg);
            }
        }
    }

    public void storeSession(String peerName, SessionManager session) {
        sessions.put(peerName, session);
    }

    public SessionManager getPendingSession(String peerName) {
        return pendingSessions.get(peerName);
    }

    public void removePendingSession(String peerName) {
        pendingSessions.remove(peerName);
    }

    public SessionManager getSession(String peerName) {
        return sessions.get(peerName);
    }

    public boolean hasSession(String peerName) {
        return sessions.containsKey(peerName);
    }

    public void removeSession(String peerName) {
        sessions.remove(peerName);
    }
}