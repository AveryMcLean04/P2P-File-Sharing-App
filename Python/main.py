import socket
import time
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceListener

# --- Project Constants ---
SERVICE_TYPE = "_cisc468secshare._tcp.local."
PORT = 5000
USERNAME = "PythonUser"

class PeerListener(ServiceListener):
    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info:
            # Convert binary IP to string
            addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
            print(f"\n[+] Peer Discovered!")
            print(f"    Name: {name}")
            print(f"    IP: {addresses[0]}:{info.port}")
            # Decode properties (TXT records)
            props = {k.decode(): v.decode() if v else None for k, v in info.properties.items()}
            print(f"    Metadata: {props}")

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f"\n[-] Peer {name} has left the network.")

def run_discovery():
    # 1. Gather local network info
    local_hostname = socket.gethostname()
    local_ip = socket.gethostbyname(local_hostname)
    
    # 2. Define our service (How others see us)
    # The name must end with the service type
    instance_name = f"{USERNAME}.{SERVICE_TYPE}"
    
    info = ServiceInfo(
        type_=SERVICE_TYPE,
        name=instance_name,
        addresses=[socket.inet_aton(local_ip)],
        port=PORT,
        properties={
            'user': USERNAME,
            'status': 'available',
            'lib': 'python-zeroconf'
        }
    )

    zc = Zeroconf()
    
    try:
        print(f"[*] Starting mDNS on {local_ip}:{PORT}...")
        print(f"[*] Registering as: {instance_name}")
        zc.register_service(info)

        # 3. Start listening for others
        listener = PeerListener()
        browser = ServiceBrowser(zc, SERVICE_TYPE, listener)

        print("[*] Listening for peers... (Press Ctrl+C to exit)")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        zc.unregister_service(info)
        zc.close()

if __name__ == "__main__":
    run_discovery()