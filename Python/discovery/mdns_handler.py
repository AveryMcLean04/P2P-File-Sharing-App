import socket
import logging
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceListener

logger = logging.getLogger("mDNSHandler")

class MDNSHandler(ServiceListener):
    def __init__(self, user_id: str, port: int, service_type: str = "_cisc468secshare._tcp.local."):
        self.user_id = user_id
        self.port = port
        self.service_type = service_type
        self.zeroconf = Zeroconf()
        self.peers = {}  # Stores {user_id: {"ip": ip, "port": port}}

    def register_service(self):
        """Broadcasts our presence to the local network."""
        local_ip = socket.gethostbyname(socket.gethostname())
        
        info = ServiceInfo(
            self.service_type,
            f"{self.user_id}.{self.service_type}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={"user_id": self.user_id},
            server=f"{self.user_id}.local.",
        )
        
        logger.info(f"Registering service: {self.user_id} on {local_ip}:{self.port}")
        self.zeroconf.register_service(info)

    def start_discovery(self):
        """Starts browsing for other peers."""
        self.browser = ServiceBrowser(self.zeroconf, self.service_type, self)

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Required by ServiceListener interface."""
        pass

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handles peers leaving the network."""
        user_id = name.split('.')[0]
        if user_id in self.peers:
            logger.info(f"Peer {user_id} left the network.")
            del self.peers[user_id]

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handles new peers joining the network."""
        info = zc.get_service_info(type_, name)
        if info:
            peer_user_id = info.properties.get(b'user_id', b'unknown').decode()
            addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
            
            if peer_user_id != self.user_id:
                self.peers[peer_user_id] = {
                    "ip": addresses[0],
                    "port": info.port
                }
                logger.info(f"Discovered Peer: {peer_user_id} at {addresses[0]}:{info.port}")

    def stop(self):
        """Cleanup on shutdown."""
        self.zeroconf.unregister_all_services()
        self.zeroconf.close()