# import socket
# import time
# from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceListener

# # --- Project Constants ---
# SERVICE_TYPE = "_cisc468secshare._tcp.local."
# PORT = 5000
# USERNAME = "PythonUser"

# class PeerListener(ServiceListener):
#     def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
#         info = zc.get_service_info(type_, name)
#         if info:
#             # Convert binary IP to string
#             addresses = [socket.inet_ntoa(addr) for addr in info.addresses]
#             print(f"\n[+] Peer Discovered!")
#             print(f"    Name: {name}")
#             print(f"    IP: {addresses[0]}:{info.port}")
#             # Decode properties (TXT records)
#             props = {k.decode(): v.decode() if v else None for k, v in info.properties.items()}
#             print(f"    Metadata: {props}")

#     def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
#         pass

#     def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
#         print(f"\n[-] Peer {name} has left the network.")

# def run_discovery():
#     # 1. Gather local network info
#     local_hostname = socket.gethostname()
#     local_ip = socket.gethostbyname(local_hostname)
    
#     # 2. Define our service (How others see us)
#     # The name must end with the service type
#     instance_name = f"{USERNAME}.{SERVICE_TYPE}"
    
#     info = ServiceInfo(
#         type_=SERVICE_TYPE,
#         name=instance_name,
#         addresses=[socket.inet_aton(local_ip)],
#         port=PORT,
#         properties={
#             'user': USERNAME,
#             'status': 'available',
#             'lib': 'python-zeroconf'
#         }
#     )

#     zc = Zeroconf()
    
#     try:
#         print(f"[*] Starting mDNS on {local_ip}:{PORT}...")
#         print(f"[*] Registering as: {instance_name}")
#         zc.register_service(info)

#         # 3. Start listening for others
#         listener = PeerListener()
#         browser = ServiceBrowser(zc, SERVICE_TYPE, listener)

#         print("[*] Listening for peers... (Press Ctrl+C to exit)")
#         while True:
#             time.sleep(1)

#     except KeyboardInterrupt:
#         print("\n[*] Shutting down...")
#     finally:
#         zc.unregister_service(info)
#         zc.close()

# if __name__ == "__main__":
#     run_discovery()


import socket
import time
import logging
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser, ServiceListener

# Configure logging to help debug mDNS noise
logging.basicConfig(level=logging.ERROR)

SERVICE_TYPE = "_cisc468secshare._tcp.local."
PORT = 5000
USERNAME = "PythonUser"
# Example fingerprint for Step 2 (Replace with your actual key hash later)
PUB_KEY_FPRINT = "sha256:a1b2c3d4..." 

def get_local_ip():
    """Finds the actual local IP address (e.g., 192.168.x.x)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

class PeerListener(ServiceListener):
    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        # Ignore our own registration
        if USERNAME in name:
            return

        info = zc.get_service_info(type_, name)
        if info:
            addrs = [socket.inet_ntoa(a) for a in info.addresses]
            # Convert properties from bytes to strings
            props = {k.decode(): v.decode() if v else "" for k, v in info.properties.items()}
            
            print(f"\n[+] Peer Online: {props.get('user', 'Unknown')}")
            print(f"    Endpoint:   {addrs[0]}:{info.port}")
            print(f"    Fingerprint: {props.get('fprint', 'None')}")

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f"\n[-] Peer Offline: {name.split('.')[0]}")

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass

def run_discovery():
    local_ip = get_local_ip()
    instance_name = f"{USERNAME}.{SERVICE_TYPE}"
    
    # Pack metadata into the TXT records
    properties = {
        'user': USERNAME,
        'fprint': PUB_KEY_FPRINT, # Helps with Step 2 Mutual Auth
        'ver': '1.0'
    }

    info = ServiceInfo(
        type_=SERVICE_TYPE,
        name=instance_name,
        addresses=[socket.inet_aton(local_ip)],
        port=PORT,
        properties=properties
    )

    zc = Zeroconf()
    
    try:
        print(f"[*] Broadcasting as {USERNAME} on {local_ip}:{PORT}")
        zc.register_service(info)

        listener = PeerListener()
        # The browser starts a background thread automatically
        browser = ServiceBrowser(zc, SERVICE_TYPE, listener)

        print("[*] Peer Discovery Active. Enter 'q' to quit or just wait...")
        while True:
            cmd = input("> ")
            if cmd.lower() == 'q':
                break
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        print("[*] Cleaning up mDNS...")
        zc.unregister_service(info)
        zc.close()

if __name__ == "__main__":
    run_discovery()