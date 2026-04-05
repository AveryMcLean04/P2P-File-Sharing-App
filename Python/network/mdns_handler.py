import socket
import base64
from typing import Dict, Optional
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceListener

class MDNSHandler(ServiceListener):
    """
    Handles decentralized peer discovery using Multicast DNS (mDNS).
    Enables local network presence broadcasting and peer detection.
    """
    def __init__(self, app, user_id: str, port: int, service_type: str = "_cisc468secshare._tcp.local."):
        self.app = app
        self.user_id = user_id
        self.port = port
        self.service_type = service_type
        
        self.zeroconf = Zeroconf()
        self.browser: Optional[ServiceBrowser] = None
        self.peers: Dict[str, Dict] = {}

    def _get_local_ip(self) -> str:
        """Determines the primary reachable local IP address."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            ip = s.getsockname()[0]
        except Exception as e:
            self.app.log("error", f"IP Discovery Error: {e}")
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def register_service(self) -> None:
        """Registers this node with identity keys in the mDNS TXT records."""
        try:
            local_ip = self._get_local_ip()
            pub_key = base64.b64encode(self.app.auth_manager.get_public_key()).decode('utf-8')

            info = ServiceInfo(
                type_=self.service_type,
                name=f"{self.user_id}.{self.service_type}",
                addresses=[socket.inet_aton(local_ip)],
                port=self.port,
                properties={"user_id": self.user_id, "public_key": pub_key},
                server=f"{self.user_id}.local.",
            )

            self.app.log("network", f"Registering mDNS at {local_ip}:{self.port}")
            self.zeroconf.register_service(info)
        except Exception as e:
            self.app.log("error", f"mDNS Registration failed: {e}")

    def start_discovery(self) -> None:
        """Starts the browser to listen for other nodes of the same service type."""
        self.app.log("network", "Starting mDNS peer discovery...")
        self.browser = ServiceBrowser(self.zeroconf, self.service_type, self)

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Callback for when a new peer is discovered on the network."""
        info = zc.get_service_info(type_, name)
        if not info: return

        props = {
            (k.decode() if isinstance(k, bytes) else k): 
            (v.decode() if isinstance(v, bytes) else v) 
            for k, v in info.properties.items()
        }
        
        peer_id = props.get("user_id", "unknown")
        if peer_id == self.user_id or peer_id == "unknown": return

        addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
        if addresses:
            self.peers[peer_id] = {
                "ip": addresses[0],
                "port": info.port,
                "public_key": props.get("public_key")
            }
            self.app.log("network", f"Discovered Peer: {peer_id} at {addresses[0]}:{info.port}")

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Callback for when a peer leaves the network."""
        peer_id = name.split('.')[0]
        if peer_id in self.peers:
            self.app.log("network", f"Peer Offline: {peer_id}")
            del self.peers[peer_id]

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Callback for when peer service information is updated."""
        self.add_service(zc, type_, name)

    def stop(self) -> None:
        """Gracefully unregisters services and shuts down the mDNS listener."""
        self.app.log("network", "Stopping mDNS services...")
        try:
            if self.browser: self.browser.cancel()
            self.zeroconf.unregister_all_services()
            self.zeroconf.close()
        except Exception as e:
            self.app.log("error", f"mDNS shutdown error: {e}")