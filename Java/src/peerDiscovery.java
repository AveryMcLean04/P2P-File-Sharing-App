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

public class PeerDiscovery {

    static final String SERVICE_TYPE = "_cisc468secshare._tcp.local.";

    static final Map<String, String[]> activePeers = new ConcurrentHashMap<>();
    // ADDED: tracks pending incoming transfer requests waiting for accept/reject
    static final Map<String, String[]> pendingTransfers = new ConcurrentHashMap<>();

    static InetAddress getLocalNetworkAddress() throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByName("8.8.8.8"), 80);
            return InetAddress.getByName(socket.getLocalAddress().getHostAddress());
        }
    }

    public static void main(String[] args) throws Exception {
        final int PORT = (args.length > 1) ? Integer.parseInt(args[1]) : 5000;
        Console console = System.console();
        char[] password = console.readPassword("Enter password for this session: ");

        String myName = (args.length > 0) ? args[0] : "Bob_java";

        IdentityManager identity = new IdentityManager(myName);
        identity.loadOrGenerate(password);

        Arrays.fill(password, '\0');


        System.out.println("Step 1: getting local address...");
        InetAddress localAddress = getLocalNetworkAddress();
        System.out.println("Step 2: local address = " + localAddress.getHostAddress());
        JmDNS jmdns = JmDNS.create(localAddress);
        System.out.println("Step 3: jmdns created");

        String pubKeyBase64 = Base64.getEncoder().encodeToString(identity.getPublicKeyBytes());
        Map<String, String> props = new HashMap<>();
        props.put("user_id", myName);
        props.put("public_key", pubKeyBase64);
        ServiceInfo info = ServiceInfo.create(SERVICE_TYPE, myName + "." + SERVICE_TYPE, PORT, 0, 0, props);
        jmdns.registerService(info);
        System.out.println("Registered as: " + myName);

        NetworkManager network = new NetworkManager(PORT, identity, myName);
        FileManager fileManager = new FileManager(myName);
        MessageDispatcher dispatcher = new MessageDispatcher(network, identity, myName, fileManager);
        network.setDispatcher(dispatcher);
        network.startServer();

        jmdns.addServiceListener(SERVICE_TYPE, new ServiceListener() {
            public void serviceAdded(ServiceEvent event) {
                // Request info twice with a short delay — helps across machines
                jmdns.requestServiceInfo(event.getType(), event.getName());
                new Thread(() -> {
                    try { Thread.sleep(1000); } catch (InterruptedException e) {}
                    jmdns.requestServiceInfo(event.getType(), event.getName());
                }).start();
}
            public void serviceResolved(ServiceEvent event) {
                if (event.getName().startsWith(myName)) return;
                String address = event.getInfo().getHostAddresses()[0];
                int peerPort = event.getInfo().getPort();

                byte[] pubKeyProp = event.getInfo().getPropertyBytes("public_key");
                String peerPubKey = pubKeyProp != null ? new String(pubKeyProp) : null;

                byte[] userIdProp = event.getInfo().getPropertyBytes("user_id");
                String peerId = userIdProp != null ? new String(userIdProp) : event.getName().split("\\.")[0];

                activePeers.put(peerId, new String[]{address, String.valueOf(peerPort), peerPubKey});
                System.out.println("\n[+] Peer found: " + peerId + " @ " + address + ":" + peerPort);
                System.out.print(myName + " > ");
            }
            public void serviceRemoved(ServiceEvent event) {
                byte[] userIdProp = event.getInfo() != null ? event.getInfo().getPropertyBytes("user_id") : null;
                String peerId = userIdProp != null ? new String(userIdProp) : event.getName().split("\\.")[0];
                activePeers.remove(peerId);
                System.out.println("\n[-] Peer left: " + peerId);
                System.out.print(myName + " > ");
            }
        });

        System.out.println("\n==================================================");
        System.out.println("        SECURE P2P: " + myName + " (Port " + PORT + ")");
        System.out.println("  Type 'help' for commands");
        System.out.println("==================================================");

        Scanner scanner = new Scanner(System.in);
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
                    System.out.println("-------------------------------------------");
                    System.out.println("list         | List discovered peers");
                    System.out.println("connect      | Handshake with a peer");
                    System.out.println("chat         | Send encrypted message to a peer");  // ADDED
                    System.out.println("fetch        | Request file list from a peer");
                    System.out.println("exit         | Shut down");
                    break;

                case "list":
                    if (activePeers.isEmpty()) {
                        System.out.println("[-] No peers discovered.");
                    } else {
                        for (Map.Entry<String, String[]> entry : activePeers.entrySet()) {
                            String sessionStatus = network.hasSession(entry.getKey()) ? "Encrypted-Session" : "No-Session";
                            System.out.println(" > " + entry.getKey() + " [" + entry.getValue()[0] + ":" + entry.getValue()[1] + "] " + sessionStatus);
                        }
                    }
                    break;

                case "connect":
                    if (activePeers.isEmpty()) {
                        System.out.println("[-] No active peers to connect to.");
                    } else {
                        System.out.print("Connect to: ");
                        String target = scanner.nextLine().trim();
                        if (!activePeers.containsKey(target)) {
                            System.out.println("[-] Peer '" + target + "' not found.");
                        } else {
                            String[] peer = activePeers.get(target);
                            network.connectToPeer(peer[0], Integer.parseInt(peer[1]), target);
                        }
                    }
                    break;

                // ADDED: send an encrypted chat message to a peer with an active session
                case "chat": {
                    System.out.print("Chat with: ");
                    String target = scanner.nextLine().trim();
                    if (!activePeers.containsKey(target)) {
                        System.out.println("[-] Peer '" + target + "' not found.");
                        break;
                    }
                    if (!network.hasSession(target)) {
                        System.out.println("[-] No secure session with " + target + ". Run 'connect' first.");
                        break;
                    }
                    System.out.print("Message: ");
                    String message = scanner.nextLine();
                    try {
                        byte[] encrypted = network.getSession(target).encrypt(message.getBytes("UTF-8"));
                        String encB64    = Base64.getEncoder().encodeToString(encrypted);
                        // Python expects "payload":"<base64>" (bare string, not an object)
                        String[] peer = activePeers.get(target);
                        String msg = "{\"type\":\"CHAT_MESSAGE\",\"sender\":\"" + myName + "\",\"payload\":\"" + encB64 + "\"}";
                        network.sendMessage(peer[0], Integer.parseInt(peer[1]), msg);
                    } catch (Exception e) {
                        System.out.println("[-] Encrypt failed: " + e.getMessage());
                    }
                    break;
                }

                case "fetch":
                    System.out.print("Fetch list from: ");
                    String target = scanner.nextLine().trim();
                    if (!activePeers.containsKey(target)) {
                        System.out.println("[-] Peer '" + target + "' not found.");
                    } else {
                        String[] peer = activePeers.get(target);
                        String msg = "{\"type\":\"FILE_LIST_REQUEST\",\"sender\":\"" + myName + "\",\"payload\":{}}";
                        network.sendMessage(peer[0], Integer.parseInt(peer[1]), msg);
                    }
                    break;

                case "exit":
                    System.out.println("[*] Shutting down...");
                    // ADDED: notify all peers before leaving, matches Python's shutdown()
                    network.broadcastPeerLeft(myName, activePeers);
                    jmdns.unregisterAllServices();
                    jmdns.close();
                    System.exit(0);
                    break;

                default:
                    System.out.println("[-] Unknown command '" + cmd + "'. Type 'help' for options.");
            }
        }
    }
}