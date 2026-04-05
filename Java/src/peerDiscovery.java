import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceInfo;
import javax.jmdns.ServiceListener;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.io.Console;

/**
 * Main entry point for the P2P file sharing application.
 * Handles the CLI, local peer discovery using mDNS, 
 * and coordinates the initialization of the identity and file management systems, as well as the network server.
 */

public class PeerDiscovery {

    static final String SERVICE_TYPE = "_cisc468secshare._tcp.local.";

    static final Map<String, String[]> activePeers = new ConcurrentHashMap<>();
    static final Map<String, String[]> pendingTransfers = new ConcurrentHashMap<>();
    static final Map<String, String[]> pendingOffers = new ConcurrentHashMap<>();
    static final Map<String, String> verifiedCatalogs = new ConcurrentHashMap<>();

    static String autoApproveFile = null;

    static InetAddress getLocalNetworkAddress() throws Exception {
        /**
         * Helper to find the local IP address by trying to connect
         * to an external socket
         */
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByName("8.8.8.8"), 80);
            return InetAddress.getByName(socket.getLocalAddress().getHostAddress());
        }
    }

    public static void main(String[] args) throws Exception {
        /**
         * Sets up the environment, handles user login, starts
         * network listener and runs the main loop
         */
        final int PORT = (args.length > 1) ? Integer.parseInt(args[1]) : 5000;
        String myName = (args.length > 0) ? args[0] : "Bob_java";

        // Securely read master password for identity and vault
        Console console = System.console();
        char[] password;
        if (console != null) {
            password = console.readPassword("Enter your Master Password (used for Identity & Vault): ");
        } else {
            System.out.print("Enter your Master Password (used for Identity & Vault): ");
            Scanner scanner = new Scanner(System.in);
            password = scanner.nextLine().toCharArray();
        }

        // Initialize security and file systems
        IdentityManager identity = new IdentityManager(myName);
        identity.loadOrGenerate(password);

        FileManager fileManager = new FileManager(myName);
        fileManager.unlockVault(password);

        // Clear password from memory after use
        Arrays.fill(password, '\0');

        // make sure the vault is locked on shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("\n[SYSTEM] Performing graceful shutdown...");
            fileManager.lockVaultAndCleanup();
        }));

        // Start mDNS discovery and network server
        InetAddress localAddress = getLocalNetworkAddress();
        System.out.println("[NETWORK] Starting mDNS peer discovery...");
        JmDNS jmdns = JmDNS.create(localAddress);

        // Broadcast that we are online with our public key
        String pubKeyBase64 = Base64.getEncoder().encodeToString(identity.getPublicKeyBytes());
        Map<String, String> props = new HashMap<>();
        props.put("user_id", myName);
        props.put("public_key", pubKeyBase64);
        ServiceInfo info = ServiceInfo.create(SERVICE_TYPE, myName, PORT, 0, 0, props);
        jmdns.registerService(info);
        System.out.println("[NETWORK] Registering mDNS: " + myName + " at " + localAddress.getHostAddress() + ":" + PORT);

        // Start the network components
        NetworkManager network = new NetworkManager(PORT, identity, myName);
        MessageDispatcher dispatcher = new MessageDispatcher(network, identity, myName, fileManager);
        network.setDispatcher(dispatcher);
        network.startServer();

        // Listen for mDNS peer events
        jmdns.addServiceListener(SERVICE_TYPE, new ServiceListener() {
            public void serviceAdded(ServiceEvent event) {
                jmdns.requestServiceInfo(event.getType(), event.getName());
            }

            public void serviceResolved(ServiceEvent event) {
                try {
                    if (event.getName().equals(myName)) return;

                    String[] addresses = event.getInfo().getHostAddresses();
                    if (addresses == null || addresses.length == 0) return; 
                    
                    String address = addresses[0];
                    int peerPort = event.getInfo().getPort();

                    byte[] pubKeyProp = event.getInfo().getPropertyBytes("public_key");
                    String peerPubKey = pubKeyProp != null ? new String(pubKeyProp) : null;

                    byte[] userIdProp = event.getInfo().getPropertyBytes("user_id");
                    String peerId = userIdProp != null ? new String(userIdProp) : event.getName().split("\\.")[0];

                    activePeers.put(peerId, new String[]{address, String.valueOf(peerPort), peerPubKey});
                    System.out.print("\r\033[K[NETWORK] Discovered Peer: " + peerId + " at " + address + ":" + peerPort + "\n" + myName + " > ");
                    
                } catch (Exception e) {
                    System.out.print("\r\033[K[ERROR] Network resolution error for " + event.getName() + ": " + e.getMessage() + "\n" + myName + " > ");
                }
            }

            public void serviceRemoved(ServiceEvent event) {
                byte[] userIdProp = event.getInfo() != null ? event.getInfo().getPropertyBytes("user_id") : null;
                String peerId = userIdProp != null ? new String(userIdProp) : event.getName().split("\\.")[0];
                activePeers.remove(peerId);
                System.out.print("\r\033[K[NETWORK] Peer Offline: " + peerId + "\n" + myName + " > ");
            }
        });

        // Banner printed post-vault unlock
        System.out.println("\n==================================================");
        String title = "SECURE P2P: " + myName;
        int padding = (50 - title.length()) / 2;
        System.out.printf("%" + (padding + title.length()) + "s\n", title);
        System.out.println("==================================================");
        System.out.println("[SYSTEM] Vault Unlocked. System Ready.");

        // Main loop for input
        Scanner scanner = new Scanner(System.in);
        String target;
        while (true) {
            System.out.print("\n" + myName + " > ");
            if (!scanner.hasNextLine()) break;
            String input = scanner.nextLine().trim();
            if (input.isEmpty()) continue;

            String[] parts = input.split(" ");
            String cmd = parts[0].toLowerCase();

            switch (cmd) {
                case "help":
                    System.out.println("\nCOMMAND      | DESCRIPTION");
                    System.out.println("----------------------------------------------------");
                    System.out.println("list         | List discovered peers");
                    System.out.println("connect      | Handshake with a peer");
                    System.out.println("chat         | Send encrypted message to a peer");
                    System.out.println("fetch        | Request file list from a peer");
                    System.out.println("request      | Request a file from a peer");
                    System.out.println("send         | Offer a file to a peer");
                    System.out.println("import       | Move files from staging to vault");
                    System.out.println("migrate      | Migrate Keys");
                    System.out.println("exit         | Shut down");
                    break;

                case "list":
                    if (activePeers.isEmpty()) {
                        System.out.println("[SYSTEM] No active peers found on local network.");
                    } else {
                        System.out.println("\n--- Discovered Peers (" + activePeers.size() + ") ---");
                        for (Map.Entry<String, String[]> entry : activePeers.entrySet()) {
                            String sessionStatus = network.hasSession(entry.getKey()) ? "SECURE-SESSION" : "No-Session";
                            System.out.println(" > " + entry.getKey() + " [" + entry.getValue()[0] + ":" + entry.getValue()[1] + "] Status: " + sessionStatus);
                        }
                    }
                    break;

                case "import":
                    System.out.println("[SYSTEM] Importing files from staging area to vault...");
                    fileManager.importFromStaging();
                    break;
                
                case "migrate":
                    System.out.println("\n[SYSTEM] KEY MIGRATION WARNING");
                    System.out.println("This will destroy your current Identity Key and generate a new one.");
                    System.out.println("Your peers will be notified securely.");
                    
                    char[] migPassword;
                    if (System.console() != null) {
                        migPassword = System.console().readPassword("Enter your Master Password to authorize: ");
                    } else {
                        System.out.print("Enter your Master Password to authorize: ");
                        migPassword = scanner.nextLine().toCharArray();
                    }

                    try {
                        // generate new keypair, sign it with old key
                        String[] migrationData = identity.migrateKey(migPassword);
                        String newKeyB64 = migrationData[0];
                        String sigB64 = migrationData[1];

                        java.util.Arrays.fill(migPassword, '\0');

                        String payload = "{" +
                            "\"new_identity_key\":\"" + newKeyB64 + "\"," +
                            "\"signature\":\"" + sigB64 + "\"" +
                        "}";
                        String msg = "{\"type\":\"KEY_MIGRATION_NOTIFY\",\"sender\":\"" + myName + "\",\"payload\":" + payload + "}";

                        // Broadcast new key to all active peers
                        if (activePeers.isEmpty()) {
                            System.out.println("[SYSTEM] Key migrated locally. No active peers to notify.");
                        } else {
                            for (Map.Entry<String, String[]> entry : activePeers.entrySet()) {
                                String[] peer = entry.getValue();
                                network.sendMessage(peer[0], Integer.parseInt(peer[1]), msg);
                            }
                            System.out.println("[SECURITY] New identity generated and broadcasted to active sessions.");
                        }
                    } catch (Exception e) {
                        System.out.println("[ERROR] Migration failed: " + e.getMessage());
                    }
                    break;

                case "connect": {
                    System.out.print("Connect to (UserID): ");
                    target = scanner.nextLine().trim();
                    
                    if (!activePeers.containsKey(target)) {
                        System.out.println("[ERROR] Peer '" + target + "' not found, make sure they are online and discoverable.");
                        break;
                    }
                    String[] peer = activePeers.get(target);
                    network.connectToPeer(peer[0], Integer.parseInt(peer[1]), target);
                    // below was used for java to java testing on the same machine, but doesn't reliably work
                    // so it has been removed from the main flow
                    // } else {
                    //     /**
                    //      * Manual connection fallback.
                    //      * mDNS works reliably across devices on the same network, but can fail
                    //      * when running multiple clients on the same machine (e.g. during local testing),
                    //      * since JmDNS may not resolve loopback addresses correctly. This fallback
                    //      * allows a direct IP and port to be entered so connections can still be made.
                    //      */
                    //     System.out.println("[SYSTEM] Peer not found via mDNS. Manual connection available.");
                    //     System.out.print("Enter IP Address (e.g., 127.0.0.1): ");
                    //     String manualIp = scanner.nextLine().trim();
                    //     System.out.print("Enter Port (e.g., 5001): ");
                    //     String manualPort = scanner.nextLine().trim();
                        
                    //     // Register the peer manually so session state can be tracked
                    //     activePeers.put(target, new String[]{manualIp, manualPort, null});
                    //     network.connectToPeer(manualIp, Integer.parseInt(manualPort), target);
                    // }
                    break;
                }

                case "chat": {
                    System.out.print("Recipient: ");
                    target = scanner.nextLine().trim();
                    if (!activePeers.containsKey(target)) {
                        System.out.println("[ERROR] Peer '" + target + "' not found.");
                        break;
                    }
                    if (!network.hasSession(target)) {
                        System.out.println("[ERROR] Access Denied: No secure session with " + target + ".");
                        break;
                    }
                    System.out.print("Message for " + target + ": ");
                    String message = scanner.nextLine();
                    try {
                        byte[] encrypted = network.getSession(target).encrypt(message.getBytes("UTF-8"));
                        String encB64    = Base64.getEncoder().encodeToString(encrypted);
                        String[] peer = activePeers.get(target);
                        String msg = "{\"type\":\"CHAT_MESSAGE\",\"sender\":\"" + myName + "\",\"payload\":\"" + encB64 + "\"}";
                        network.sendMessage(peer[0], Integer.parseInt(peer[1]), msg);
                        System.out.println("[SYSTEM] Message sent to " + target + ".");
                    } catch (Exception e) {
                        System.out.println("[ERROR] Encryption failed: " + e.getMessage());
                    }
                    break;
                }

                case "fetch":
                    System.out.print("Fetch file list from (UserID): ");
                    target = scanner.nextLine().trim();
                    if (!activePeers.containsKey(target)) {
                        System.out.println("[ERROR] Peer '" + target + "' not found.");
                    } else if (!network.hasSession(target)) {
                        System.out.println("[ERROR] Access Denied: No secure session with " + target + ".");
                    } else {
                        String[] peer = activePeers.get(target);
                        String msg = "{\"type\":\"FILE_LIST_REQUEST\",\"sender\":\"" + myName + "\",\"payload\":{}}";
                        network.sendMessage(peer[0], Integer.parseInt(peer[1]), msg);
                        System.out.println("[SYSTEM] Syncing catalog with " + target + "...");
                    }
                    break;

                case "exit":
                    System.out.println("[SYSTEM] Performing graceful shutdown...");
                    network.broadcastPeerLeft(myName, activePeers);
                    jmdns.unregisterAllServices();
                    jmdns.close();
                    System.out.println("[SYSTEM] Goodbye.");
                    System.exit(0);
                    break;

                case "send": {
                    System.out.print("Recipient UserID: ");
                    String sendTarget = scanner.nextLine().trim();
                    if (!activePeers.containsKey(sendTarget)) {
                        System.out.println("[ERROR] Peer '" + sendTarget + "' not found.");
                        break;
                    }
                    if (!network.hasSession(sendTarget)) {
                        System.out.println("[ERROR] Access Denied: No secure session with " + sendTarget + ".");
                        break;
                    }
                    
                    System.out.print("Filename to send: ");
                    String sendFileName = scanner.nextLine().trim();
                    
                    java.nio.file.Path filePath = java.nio.file.Paths.get("data_" + myName + "/shared/" + sendFileName);
                    if (!java.nio.file.Files.exists(filePath)) {
                        System.out.println("[ERROR] Error: File '" + sendFileName + "' not found in your shared folder.");
                        break;
                    }

                    try {
                        autoApproveFile = sendFileName; 
                        
                        String[] peer = activePeers.get(sendTarget);
                        String msg = "{\"type\":\"PUSH_PROPOSAL\",\"sender\":\"" + myName + "\",\"payload\":{\"filename\":\"" + sendFileName + "\"}}";
                        network.sendMessage(peer[0], Integer.parseInt(peer[1]), msg);
                        System.out.println("[TRANSFER] Push proposal for '" + sendFileName + "' sent to " + sendTarget + ".");
                    } catch (Exception e) {
                        System.out.println("[ERROR] Send offer failed: " + e.getMessage());
                    }
                    break;
                }

                case "request":
                    System.out.print("Request from: ");
                    String requestTarget = scanner.nextLine().trim();
                    if (!activePeers.containsKey(requestTarget)) {
                        System.out.println("[ERROR] Peer '" + requestTarget + "' not found.");
                        break;
                    }
                    if (!network.hasSession(requestTarget)) {
                        System.out.println("[ERROR] Access Denied: No secure session with " + requestTarget + ".");
                        break;
                    }
    
                    System.out.print("Filename: ");
                    String reqFileName = scanner.nextLine().trim();
    
                    try {
                        String[] peer = activePeers.get(requestTarget);
                        String msg = "{\"type\":\"TRANSFER_REQUEST\",\"sender\":\"" + myName + "\",\"payload\":{\"filename\":\"" + reqFileName + "\"}}";
                        network.sendMessage(peer[0], Integer.parseInt(peer[1]), msg);
                        System.out.println("[TRANSFER] Requested '" + reqFileName + "' from " + requestTarget + ". Waiting for peer...");
                    } catch (Exception e) {
                        System.out.println("[ERROR] Request failed: " + e.getMessage());
                    }
                    break;

                case "y":
                case "yes": {
                    if (!pendingOffers.isEmpty()) {
                        Map.Entry<String, String[]> entry = pendingOffers.entrySet().iterator().next();
                        String sender = entry.getKey();
                        String fileName = entry.getValue()[0];
                        pendingOffers.remove(sender);
        
                        String[] peer = activePeers.get(sender);
                        String msg = "{\"type\":\"TRANSFER_REQUEST\",\"sender\":\"" + myName + "\",\"payload\":{\"filename\":\"" + fileName + "\"}}";
                        network.sendMessage(peer[0], Integer.parseInt(peer[1]), msg);
                        System.out.println("[TRANSFER] Accepted push. Requesting '" + fileName + "'...");
                        break;
                    }
    
                    if (!pendingTransfers.isEmpty()) {
                        Map.Entry<String, String[]> entry = pendingTransfers.entrySet().iterator().next();
                        String requester = entry.getKey();
                        String fileName = entry.getValue()[0];
                        pendingTransfers.remove(requester);
        
                        dispatcher.executeApprovedTransfer(requester, fileName);
                        break;
                    }
    
                    System.out.println("[ERROR] No pending transfers or offers to approve.");
                    break;
                }

                case "n":
                case "no": {
                    if (pendingTransfers.isEmpty() && pendingOffers.isEmpty()) {
                        System.out.println("[ERROR] No pending transfers to reject.");
                        break;
                    }

                    if (!pendingOffers.isEmpty()) {
                        Map.Entry<String, String[]> entry = pendingOffers.entrySet().iterator().next();
                        String sender = entry.getKey();
                        String fileName = entry.getValue()[0];
                        pendingOffers.remove(sender);

                        String[] peerInfo = activePeers.get(sender);
                        if (peerInfo != null) {
                            String msg = "{\"type\":\"OFFER_REJECT\",\"sender\":\"" + myName + "\",\"payload\":{\"filename\":\"" + fileName + "\"}}";
                            network.sendMessage(peerInfo[0], Integer.parseInt(peerInfo[1]), msg);
                        }
                        System.out.println("[SYSTEM] Transfer request denied.");
                        break;
                    }

                    Map.Entry<String, String[]> entry = pendingTransfers.entrySet().iterator().next();
                    String requester = entry.getKey();
                    String fileName = entry.getValue()[0];
                    pendingTransfers.remove(requester);
                    
                    System.out.println("[SYSTEM] Transfer request denied.");
                    
                    String[] peerInfo = activePeers.get(requester);
                    if (peerInfo != null) {
                        String msg = "{\"type\":\"TRANSFER_REJECT\",\"sender\":\"" + myName + "\",\"payload\":{\"filename\":\"" + fileName + "\"}}";
                        network.sendMessage(peerInfo[0], Integer.parseInt(peerInfo[1]), msg);
                    }
                    break;
                }

                default:
                    System.out.println("[ERROR] Unknown command: '" + cmd + "'. Type 'help' for list.");
            }
        }
    }
}