import java.io.*;
import java.net.*;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Handles all network communication.
 * Responsible for starting the server listener, sending JSON messages to peers, initiating
 * the cryptographic handshake process, and maintains session states for connected peers.
 */

public class NetworkManager {

    private final int port;
    private ServerSocket serverSocket;
    private final IdentityManager identity;
    private final String myName;
    private MessageDispatcher dispatcher;

    // one map for sessions that are already established, and one for sessions that are in the process of being established
    private final Map<String, SessionManager> pendingSessions = new ConcurrentHashMap<>();
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
        /**
         * Starts a thread that listens for incoming TCP connections on the specified port.
         * When a peer connects, it spawns a new thread to handle that message.
         */
        Thread serverThread = new Thread(() -> {
            try {
                serverSocket = new ServerSocket(port);
                System.out.println("[NETWORK] Listener started on port " + port);
                while (true) {
                    Socket client = serverSocket.accept();
                    // use multithreading to ensure a slow or unresponsive peer doesn't block the server
                    new Thread(() -> handleConnection(client)).start();
                }
            } catch (IOException e) {
                System.out.println("[ERROR] Server error: " + e.getMessage());
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();
    }

    private void handleConnection(Socket client) {
        /**
         * Reads the raw JSON message from the client's socket, converts it to a UTF-8 string,
         * and passes it to the MessageDispatcher for processing.
         */
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
            System.out.println("[ERROR] Error handling client: " + e.getMessage());
        }
    }

    public void sendMessage(String address, int port, String jsonMessage) {
        /**
         * Opens a temporary socket to a target peer, sends the given JSON message,
         * and closes the socket immediately after.
         */
        try (Socket socket = new Socket(address, port)) {
            byte[] data = (jsonMessage + "\n").getBytes("UTF-8");
            socket.getOutputStream().write(data);
            socket.getOutputStream().flush();
            socket.shutdownOutput(); 
        } catch (IOException e) {
            System.out.println("[ERROR] Failed to send message to " + address + ":" + port + " — " + e.getMessage());
        }
    }

    public void connectToPeer(String address, int port, String peerName) {
        /**
         * Initiates the handshake process with a new peer
         * Generates a new ephemeral key pair, signs it with the long-term identity key,
         * sends out HANDSHAKE_INIT message, to start the secure session process
         */
        try {
            SessionManager session = new SessionManager();
            pendingSessions.put(peerName, session);

            byte[] myEphemeralRaw = session.getPublicBytes();
            byte[] mySignature    = identity.sign(myEphemeralRaw);
            byte[] myIdentityPub  = identity.getPublicKeyBytes();

            //Construct the initial greeting with the identity and ephemeral keys, and a signature to prove ownership of the identity key
            String initMsg = "{\"type\":\"HANDSHAKE_INIT\"," +
                             "\"sender\":\"" + myName + "\"," +
                             "\"payload\":{" +
                             "\"identity_key\":\""    + Base64.getEncoder().encodeToString(myIdentityPub)  + "\"," +
                             "\"ephemeral_share\":\"" + Base64.getEncoder().encodeToString(myEphemeralRaw) + "\"," +
                             "\"signature\":\""       + Base64.getEncoder().encodeToString(mySignature)    + "\"," +
                             "\"timestamp\":"         + (System.currentTimeMillis() / 1000L) +
                             "}}";

            sendMessage(address, port, initMsg);
            System.out.println("[SECURITY] Handshake dispatched to " + peerName + "...");

        } catch (Exception e) {
            System.out.println("[ERROR] Connect failed: " + e.getMessage());
            pendingSessions.remove(peerName);
        }
    }

    public void broadcastPeerLeft(String senderId, Map<String, String[]> peers) {
        /**
         * Notifies everyone in the peer list, regardless of session state,
         * that a peer has left the network so they can clean up any of their
         * own session states.
         */
        String msg = "{\"type\":\"PEER_LEFT\",\"sender\":\"" + senderId + "\",\"payload\":{}}";
        System.out.println("[NETWORK] Broadcasting exit to " + peers.size() + " peers...");
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