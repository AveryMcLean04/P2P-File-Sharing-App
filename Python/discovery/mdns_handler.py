import socket
import logging
from zeroconf import IPVersion, ServiceInfo, Zeroconf, ServiceBrowser

# Silence zeroconf internal logging to keep your CLI clean
logging.getLogger('zeroconf').setLevel(logging.CRITICAL)

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
        """Registers the service and starts the network browser."""
        local_ip = self._get_local_ip()

        # Registration: name must end with the service_type
        # We use user_id as the name prefix
        self._my_service_info = ServiceInfo(
            type_=self.service_type,
            name=f"{self.user_id}.{self.service_type}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={'user_id': self.user_id}
        )
        
        try:
            self.zeroconf.register_service(self._my_service_info)
            # Use a slightly cleaner print format to match your App's style
            print(f"[*] mDNS: Broadcasting as '{self.user_id}' on {local_ip}:{self.port}")
        except Exception as e:
            print(f"[!] mDNS Registration failed: {e}")

        # Start browsing for other peers
        self.browser = ServiceBrowser(self.zeroconf, self.service_type, self)

    def add_service(self, zc, type_, name):
        """Callback: New peer found on the network."""
        # Async fetch of service details
        info = zc.get_service_info(type_, name)
        if not info:
            return

        # Extract Peer ID - prioritize the 'user_id' property
        raw_id = info.properties.get(b'user_id')
        if raw_id:
            peer_id = raw_id.decode('utf-8')
        else:
            # Fallback: extract prefix from 'Alice.service.tcp.local.'
            peer_id = name.split('.')[0]
        
        # Don't add yourself to the peer list
        if peer_id == self.user_id:
            return

        # Extract IP address safely
        addresses = info.parsed_addresses()
        if addresses:
            address = addresses[0]
            self.discovered_peers[peer_id] = {
                "address": address,
                "port": info.port,
                "server_name": name # Keep the full mDNS name for removal
            }
            # Use \r to keep the prompt clean if the user is typing
            print(f"\n[+] Peer Found: {peer_id} ({address}:{info.port})")
            print(f"{self.user_id} > ", end="", flush=True)

    def remove_service(self, zc, type_, name):
        """Callback: Peer left the network."""
        # Find the peer by the server_name since peer_id might differ from name prefix
        target_id = None
        for pid, pdata in self.discovered_peers.items():
            if pdata.get("server_name") == name:
                target_id = pid
                break
        
        # If not found by server_name, try the name prefix
        if not target_id:
            target_id = name.split('.')[0]

        if target_id in self.discovered_peers:
            self.discovered_peers.pop(target_id, None)
            print(f"\n[-] Peer Removed: {target_id}")
            print(f"{self.user_id} > ", end="", flush=True)

    def update_service(self, zc, type_, name):
        """Handle potential IP/Port changes of an existing peer."""
        self.add_service(zc, type_, name)

    def get_active_peers(self):
        """Returns a snapshot of currently visible peers."""
        return self.discovered_peers.copy()

    def stop_discovery(self):
        """Robust shutdown of mDNS services."""
        if self.zeroconf:
            try:
                # Close() handles unregistering and stopping the browser
                self.zeroconf.close()
                self.zeroconf = None
                print("[*] mDNS services stopped.")
            except Exception as e:
                print(f"[!] mDNS shutdown warning: {e}")