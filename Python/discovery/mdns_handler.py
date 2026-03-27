import socket
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceListener
import base64

class MDNSHandler(ServiceListener):
    def __init__(self, app, user_id: str, port: int, service_type: str = "_cisc468secshare._tcp.local."):
        """
        Handles mDNS registration and peer discovery.
        :param app: The main SecureP2PApp instance for centralized logging.
        """
        self.app = app
        self.user_id = user_id
        self.port = port
        self.service_type = service_type
        self.zeroconf = Zeroconf()
        self.peers = {}  # Stores {user_id: {"ip": ip, "port": port}}
        self.browser = None

    def _get_local_ip(self):
        """Utility to find the actual local IP address used for networking."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def register_service(self):
        """Broadcasts our presence to the local network."""
        local_ip = self._get_local_ip()
        
        info = ServiceInfo(
            self.service_type,
            f"{self.user_id}.{self.service_type}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={
                "user_id": self.user_id,
                "public_key": base64.b64encode(self.app.auth_manager.get_public_key()).decode()},
            server=f"{self.user_id}.local.",
        )
        
        self.app.log("system", f"Registering mDNS: {self.user_id} on {local_ip}:{self.port}")
        self.zeroconf.register_service(info)

    def start_discovery(self):
        """Starts browsing for other peers using this class as the listener."""
        self.browser = ServiceBrowser(self.zeroconf, self.service_type, self)

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Required by ServiceListener interface."""
        pass

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handles peers leaving the network."""
        # Extract the user_id from the mDNS name (e.g., "Bob._cisc4...local.")
        peer_id = name.split('.')[0]
        if peer_id in self.peers:
            self.app.log("system", f"Peer '{peer_id}' left the network.")
            del self.peers[peer_id]

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handles new peers joining the network."""
        info = zc.get_service_info(type_, name)
        if info:
            # Zeroconf properties are bytes
            peer_user_id = info.properties.get(b'user_id', b'unknown').decode()
            addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
            
            if peer_user_id != self.user_id:
                self.peers[peer_user_id] = {
                    "ip": addresses[0],
                    "port": info.port
                }
                self.app.log("system", f"Discovered Peer: {peer_user_id} at {addresses[0]}:{info.port}")

    def stop(self):
        """Cleanup on shutdown."""
        if self.browser:
            self.browser.cancel()
        self.zeroconf.unregister_all_services()
        self.zeroconf.close()