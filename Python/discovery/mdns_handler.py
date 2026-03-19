import socket
from zeroconf import IPVersion, ServiceInfo, Zeroconf, ServiceBrowser

class MDNSHandler:
    def __init__(self, user_id="Alice_Python", port=5000, service_type="_cisc468secshare._tcp.local."):
        self.user_id = user_id
        self.port = port
        self.service_type = service_type
        self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        self.discovered_peers = {}
        self.browser = None
        self._my_service_info = None

    def _get_local_ip(self):
        """Simple, clean local IP lookup."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Connect to a non-existent external IP to determine local interface
            s.connect(('8.8.8.8', 1))
            return s.getsockname()[0]
        except Exception:
            return '127.0.0.1'
        finally:
            s.close()

    def start_discovery(self):
        """Registers Alice_Python and starts the network browser."""
        local_ip = self._get_local_ip()

        # Create service info for this instance
        self._my_service_info = ServiceInfo(
            type_=self.service_type,
            name=f"{self.user_id}.{self.service_type}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={'user_id': self.user_id}
        )
        
        self.zeroconf.register_service(self._my_service_info)
        print(f"[*] Broadcasting as {self.user_id} on {local_ip}:{self.port}")

        # Start browsing for other peers
        self.browser = ServiceBrowser(self.zeroconf, self.service_type, self)

    def add_service(self, zc, type_, name):
        """Callback: New peer found on the network."""
        info = zc.get_service_info(type_, name)
        if not info:
            return

        # Extract Peer ID from properties (fallback to name prefix)
        raw_id = info.properties.get(b'user_id', name.split('.')[0].encode())
        peer_id = raw_id.decode('utf-8')
        
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
            self.discovered_peers.pop(peer_id, None)

    def update_service(self, zc, type_, name):
        """Required by Zeroconf interface."""
        pass

    def get_active_peers(self):
        return self.discovered_peers

    def stop_discovery(self):
        """
        Robust shutdown. 
        Note: self.zeroconf.close() handles unregistering services automatically.
        """
        if self.zeroconf:
            try:
                # Close is the only call needed; it handles unregistration internally.
                # Explicitly calling unregister_all_services() often causes the crash.
                self.zeroconf.close()
                self.zeroconf = None
                print("[*] mDNS services stopped.")
            except Exception as e:
                print(f"[!] mDNS shutdown warning: {e}")