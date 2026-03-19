# P2P Secure File Sharing App (CISC 468)

A cross-platform (Python/Java) peer-to-peer file sharing application focusing on mutual authentication, perfect forward secrecy, and local network discovery.

## Connection Details
- **mDNS Service String:** `_cisc468secshare._tcp.local.`
- **Port Number:** `5000`
- **Serialization:** UTF-8 JSON (Binary data must be Base64 encoded)

---

## Project Structure
- `/python_client/`: Python 3.12 implementation (Group Member A)
- `/java_client/`: Java/Maven implementation (Group Member B)
- `/shared_test_files/`: Standard files used to verify integrity/hashes.

---

## Protocol Specifications

### 1. Peer Discovery (Requirement 1)
Clients broadcast their `user_id` via mDNS. 
- **Python:** Uses `zeroconf` library.
- **Java:** Uses `JmDNS` library.

### 2. Handshake & PFS (Requirement 2 & 8)
To ensure **Perfect Forward Secrecy**, we use an Ephemeral Diffie-Hellman exchange:
1. **Algorithm:** X25519 (ECDH).
2. **KDF:** HKDF-SHA256 to derive the session key.
3. **Session Key:** AES-256-GCM (12-byte IV, 16-byte Tag).

### 3. File Integrity (Requirement 5 & 7)
All files are hashed using **SHA-256** before transmission. The receiver must verify the hash against the decrypted file to ensure no tampering occurred.

### 4. Local Storage (Requirement 9)
Files stored in the `/data` folders are encrypted at rest.
- **Algorithm:** AES-256-CBC.
- **Key Derivation:** PBKDF2 with 100k iterations.

---

## Shared Message Formats
All messages follow this JSON structure:
```json
{
  "type": "FILE_REQ | LIST_REQ | AUTH_CHALLENGE",
  "sender": "user_id",
  "payload": { ... },
  "signature": "Base64_String"
}

# Python client:

    cd into Python

To run the python client:
    python main.py Alice 5000



# Java client:
to start:
    cd Java

create output directory (first time only):
    mkdir out

to compile:
    javac -cp "..\libs\jmdns-3.5.11.jar;..\libs\slf4j-api-1.7.36.jar;..\libs\slf4j-simple-1.7.36.jar;..\libs\bcprov-jdk18on-178.jar" -d out src\PeerDiscovery.java src\NetworkManager.java src\SessionManager.java

run:
    .\run.bat Bob_java

or to run without the bat file:
    java -cp "out;..\libs\jmdns-3.5.11.jar;..\libs\slf4j-api-1.7.36.jar;..\libs\slf4j-simple-1.7.36.jar" PeerDiscovery Bob_java

Replace Bob_java with whatever name you want to use for your peer.