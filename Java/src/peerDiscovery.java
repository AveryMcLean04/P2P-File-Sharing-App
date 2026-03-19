import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceInfo;
import javax.jmdns.ServiceListener;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class PeerDiscovery {

    static final String SERVICE_TYPE = "_cisc468secshare._tcp.local.";
    static final int PORT = 5000;

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
                System.out.println("Found peer: " + event.getName() + " @ " + address + ":" + peerPort);

                String testMsg = "{\"type\":\"FILE_LIST_REQUEST\",\"sender\":\"" + myName + "\",\"payload\":{}}";
                network.sendMessage(address, peerPort, testMsg);
            }
            public void serviceRemoved(ServiceEvent event) {
                System.out.println("Peer left: " + event.getName());
            }
        });

        System.out.println("Listening for peers... (Ctrl+C to quit)");
        Thread.sleep(Long.MAX_VALUE);
    }
}