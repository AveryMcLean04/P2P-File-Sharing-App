import javax.jmdns.JmDNS;
import javax.jmdns.ServiceInfo;
import java.io.IOException;
import java.net.InetAddress;

public class MdnsAnnouncer {
    private static final String SERVICE_TYPE = "_secfileshare._tcp.local.";

    public static void main(String[] args) throws IOException, InterruptedException {
        JmDNS jmdns = JmDNS.create(InetAddress.getLocalHost());

        ServiceInfo serviceInfo = ServiceInfo.create(
            SERVICE_TYPE,
            "MyPeer",       // unique name for this peer
            5000,           // port your app will listen on
            "Secure file share peer"
        );

        jmdns.registerService(serviceInfo);
        System.out.println("Announced on mDNS. Waiting...");

        Thread.sleep(60_000); // stay alive for a bit
        jmdns.unregisterAllServices();
        jmdns.close();
    }
}
