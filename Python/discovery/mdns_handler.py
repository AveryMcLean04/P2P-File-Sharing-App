import socket
import base64
from typing import Dict, Optional
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceListener

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
        self.browser: Optional[ServiceBrowser] = None
        self.peers: Dict[str, Dict] = {}  # {user_id: {"ip": ip, "port": port}}

    def _get_local_ip(self) -> str:
        """Utility to find the actual local IP address used for networking."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            ip = s.getsockname()[0]
        except Exception as e:
            self.app.log("system", f"IP Discovery Error: {e}. Defaulting to localhost.")
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def register_service(self) -> None:
        """Broadcasts our presence to the local network."""
        try:
            local_ip = self._get_local_ip()
            pub_key_bytes = self.app.auth_manager.get_public_key()
            encoded_key = base64.b64encode(pub_key_bytes).decode('utf-8')

            info = ServiceInfo(
                type_=self.service_type,
                name=f"{self.user_id}.{self.service_type}",
                addresses=[socket.inet_aton(local_ip)],
                port=self.port,
                properties={
                    "user_id": self.user_id,
                    "public_key": encoded_key
                },
                server=f"{self.user_id}.local.",
            )

            self.app.log("system", f"Registering mDNS: {self.user_id} at {local_ip}:{self.port}")
            self.zeroconf.register_service(info)
        except Exception as e:
            self.app.log("error", f"mDNS Registration failed: {e}")

    def start_discovery(self) -> None:
        """Starts browsing for other peers."""
        self.app.log("system", "Starting mDNS peer discovery...")
        self.browser = ServiceBrowser(self.zeroconf, self.service_type, self)

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handles new peers joining the network."""
        info = zc.get_service_info(type_, name)
        if not info:
            return

        props = {k.decode() if isinstance(k, bytes) else k: 
                 v.decode() if isinstance(v, bytes) else v 
                 for k, v in info.properties.items()}
        
        peer_id = props.get("user_id", "unknown")

        if peer_id == self.user_id or peer_id == "unknown":
            return

        addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
        if addresses:
            self.peers[peer_id] = {
                "ip": addresses[0],
                "port": info.port,
                "public_key": props.get("public_key")
            }
            self.app.log("system", f"Discovered Peer: {peer_id} at {addresses[0]}:{info.port}")

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handles peers leaving the network."""
        peer_id = name.split('.')[0]
        if peer_id in self.peers:
            self.app.log("system", f"Peer Offline: {peer_id}")
            del self.peers[peer_id]

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handles updates to existing services (e.g., IP changes)."""
        self.add_service(zc, type_, name)

    def stop(self) -> None:
        """Cleanup on shutdown."""
        self.app.log("system", "Stopping mDNS services...")
        try:
            if self.browser:
                self.browser.cancel()
            self.zeroconf.unregister_all_services()
            self.zeroconf.close()
        except Exception as e:
            self.app.log("error", f"Error during mDNS shutdown: {e}")