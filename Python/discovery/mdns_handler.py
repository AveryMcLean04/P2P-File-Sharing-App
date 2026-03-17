import socket
from zeroconf import IPVersion, ServiceInfo, Zeroconf, ServiceBrowser

class MDNSHandler:
    def __init__(self, user_id, port, service_type):
        self.user_id = user_id
        self.port = port
        self.service_type = service_type
        self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        self.discovered_peers = {} # { "user_id": {"address": str, "port": int} }

    def start_discovery(self):
        """Registers our service and starts the browser."""
        # 1. Get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Doesn't even have to be reachable; just triggers local IP lookup
            s.connect(('8.8.8.8', 1))
            local_ip = s.getsockname()[0]
        except Exception:
            local_ip = '127.0.0.1'
        finally:
            s.close()

        # 2. Register our own service
        # Service name must end in the service type
        info = ServiceInfo(
            type_=self.service_type,
            name=f"{self.user_id}.{self.service_type}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={'user_id': self.user_id}
        )
        
        self.zeroconf.register_service(info)
        print(f"[*] Broadcasting as {self.user_id} on {local_ip}:{self.port}")

        # 3. Start Browser to find others
        self.browser = ServiceBrowser(self.zeroconf, self.service_type, self)

    def add_service(self, zc, type_, name):
        """Callback: New peer found."""
        info = zc.get_service_info(type_, name)
        if info:
            # Extract Peer ID from TXT records or Name
            peer_id = info.properties.get(b'user_id', name.split('.')[0].encode()).decode()
            
            # Don't add ourselves
            if peer_id != self.user_id:
                address = socket.inet_ntoa(info.addresses[0])
                self.discovered_peers[peer_id] = {
                    "address": address,
                    "port": info.port
                }
                print(f"\n[+] Peer Found: {peer_id} ({address}:{info.port})")

    def remove_service(self, zc, type_, name):
        """Callback: Peer left the network."""
        peer_id = name.split('.')[0]
        if peer_id in self.discovered_peers:
            print(f"\n[-] Peer Removed: {peer_id}")
            del self.discovered_peers[peer_id]

    def update_service(self, zc, type_, name):
        """Required by Zeroconf but not needed for basic discovery."""
        pass

    def get_active_peers(self):
        return self.discovered_peers

    def stop_discovery(self):
        """Clean shutdown (Important for mDNS)."""
        self.zeroconf.unregister_all_services()
        self.zeroconf.close()