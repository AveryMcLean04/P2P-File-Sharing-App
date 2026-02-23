import javax.jmdns.JmDNS;
import javax.jmdns.ServiceEvent;
import javax.jmdns.ServiceListener;
import java.io.IOException;
import java.net.InetAddress;

public class MdnsListener {
    private static final String SERVICE_TYPE = "_secfileshare._tcp.local.";

    public static void main(String[] args) throws IOException, InterruptedException {
        JmDNS jmdns = JmDNS.create(InetAddress.getLocalHost());

        jmdns.addServiceListener(SERVICE_TYPE, new ServiceListener() {
            public void serviceAdded(ServiceEvent event) {
                System.out.println("Peer found: " + event.getName());
                jmdns.requestServiceInfo(event.getType(), event.getName());
            }
            public void serviceRemoved(ServiceEvent event) {
                System.out.println("Peer left: " + event.getName());
            }
            public void serviceResolved(ServiceEvent event) {
                System.out.println("Resolved: " + event.getInfo());
                // event.getInfo().getInetAddresses() gives you the IP
                // event.getInfo().getPort() gives you the port
            }
        });

        System.out.println("Listening for peers...");
        Thread.sleep(60_000);
        jmdns.close();
    }
}