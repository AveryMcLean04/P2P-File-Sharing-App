import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceInfo;
import javax.jmdns.ServiceListener;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class PeerDiscovery {

    static final String SERVICE_TYPE = "_cisc468secshare._tcp.local.";
    static final int PORT = 5000;

    // Stores discovered peers: name -> address:port
    static final Map<String, String[]> activePeers = new HashMap<>();

    static InetAddress getLocalNetworkAddress() throws Exception {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(InetAddress.getByName("8.8.8.8"), 80);
            return InetAddress.getByName(socket.getLocalAddress().getHostAddress());
        }
    }

    public static void main(String[] args) throws Exception {
        String myName = (args.length > 0) ? args[0] : "Bob_java";

        System.out.println("Step 1: getting local address...");
        InetAddress localAddress = getLocalNetworkAddress();
        System.out.println("Step 2: local address = " + localAddress.getHostAddress());
        JmDNS jmdns = JmDNS.create(localAddress);
        System.out.println("Step 3: jmdns created");

        ServiceInfo info = ServiceInfo.create(SERVICE_TYPE, myName, PORT, "");
        jmdns.registerService(info);
        System.out.println("Registered as: " + myName);

        NetworkManager network = new NetworkManager(PORT);
        network.startServer();

        jmdns.addServiceListener(SERVICE_TYPE, new ServiceListener() {
            public void serviceAdded(ServiceEvent event) {
                jmdns.requestServiceInfo(event.getType(), event.getName());
            }
            public void serviceResolved(ServiceEvent event) {
                if (event.getName().equals(myName)) return;
                String address = event.getInfo().getHostAddresses()[0];
                int peerPort = event.getInfo().getPort();
                activePeers.put(event.getName(), new String[]{address, String.valueOf(peerPort)});
                System.out.println("\n[+] Peer found: " + event.getName() + " @ " + address + ":" + peerPort);
                System.out.print(myName + " > ");  // reprint prompt
            }
            public void serviceRemoved(ServiceEvent event) {
                activePeers.remove(event.getName());
                System.out.println("\n[+] Peer left: " + event.getName());
                System.out.print(myName + " > ");  // reprint prompt
            }
        });

        // CLI loop
        System.out.println("\n==================================================");
        System.out.println("        SECURE P2P: " + myName + " (Port " + PORT + ")");
        System.out.println("  Type 'help' for commands");
        System.out.println("==================================================");

        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("\n" + myName + " > ");
            String input = scanner.nextLine().trim();
            if (input.isEmpty()) continue;

            String[] parts = input.split(" ");
            String cmd = parts[0].toLowerCase();

            switch (cmd) {
                case "help":
                    System.out.println("\nCOMMAND      | DESCRIPTION");
                    System.out.println("-------------------------------------------");
                    System.out.println("list         | List discovered peers");
                    System.out.println("fetch        | Request file list from a peer");
                    System.out.println("exit         | Shut down");
                    break;

                case "list":
                    if (activePeers.isEmpty()) {
                        System.out.println("[-] No peers discovered.");
                    } else {
                        for (Map.Entry<String, String[]> entry : activePeers.entrySet()) {
                            System.out.println(" > " + entry.getKey() + " [" + entry.getValue()[0] + ":" + entry.getValue()[1] + "]");
                        }
                    }
                    break;

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