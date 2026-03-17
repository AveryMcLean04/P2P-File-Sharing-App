import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceInfo;
import javax.jmdns.ServiceListener;
import java.net.InetAddress;

public class PeerDiscovery {

    static final String SERVICE_TYPE = "_cisc468secshare._tcp.local.";
    static final int PORT = 5000;

    public static void main(String[] args) throws Exception {
        String myName = (args.length > 0) ? args[0] : "Bob_java";

        JmDNS jmdns = JmDNS.create(InetAddress.getLocalHost());

        // Register ourselves on the network
        ServiceInfo info = ServiceInfo.create(SERVICE_TYPE, myName, PORT, "");
        jmdns.registerService(info);
        System.out.println("Registered as: " + myName);

        // Listen for other peers
        jmdns.addServiceListener(SERVICE_TYPE, new ServiceListener() {
            public void serviceAdded(ServiceEvent event) {
                jmdns.requestServiceInfo(event.getType(), event.getName());
            }
            public void serviceResolved(ServiceEvent event) {
                if (event.getName().equals(myName)) return; // ignore ourselves
                String address = event.getInfo().getHostAddresses()[0];
                System.out.println("Found peer: " + event.getName() + " @ " + address + ":" + PORT);
            }
            public void serviceRemoved(ServiceEvent event) {
                System.out.println("Peer left: " + event.getName());
            }
        });

        System.out.println("Listening for peers... (Ctrl+C to quit)");
        Thread.sleep(Long.MAX_VALUE); // just keep running
    }
}