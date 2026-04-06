# P2P Secure File Sharing App (CISC 468)

A cross-platform (Python/Java) peer-to-peer file sharing application focusing on mutual authentication, perfect forward secrecy, and local network discovery.

---

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

## Identity & Password
Each peer has a long-term Ed25519 identity keypair stored in two files:
- `identity.pub` — public key (not secret)
- `identity.key` — private key, encrypted with your password

On first run you will be prompted to set a password. Use the same password every time you run the program.
To reset your identity, simply delete both files and restart — a new keypair will be generated and you will be prompted to set a new password.

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
```

---

## Python client:

Go to the Python directory:

    cd Python

Run the python client:

    python main.py **your username** **port number**

Unit testing:

    python -m pytest tests/

---

## Java client:

Go to the Java directory:

    cd Java

Create output directory (first time only):

    mkdir out

Compile:

    javac -cp "..\libs\jmdns-3.5.11.jar;..\libs\slf4j-api-1.7.36.jar;..\libs\slf4j-simple-1.7.36.jar;..\libs\bcprov-jdk18on-1.83.jar;..\libs\junit-4.13.2.jar;..\libs\hamcrest-core-1.3.jar" -d out src\*.java test\*.java

Run the Java client:

    .\run.bat *your username* *port number*

Unit testing:

    java -cp "out;..\libs\jmdns-3.5.11.jar;..\libs\slf4j-api-1.7.36.jar;..\libs\slf4j-simple-1.7.36.jar;..\libs\bcprov-jdk18on-1.83.jar;..\libs\junit-4.13.2.jar;..\libs\hamcrest-core-1.3.jar" org.junit.runner.JUnitCore IdentityManagerTest SessionManagerTest FileManagerTest MessageDispatcherTest

## Common Workflow

The following command sequence demonstrates a typical interaction between Alice and Bob*:

| Step | User   | Command                      | Description                                      |
|------|--------|------------------------------|--------------------------------------------------|
| 1    | Alice  | `list`                       | Discover peers on the local network              |
| 2    | Alice  | `connect bob`                | Initiate secure handshake with Bob               |
| 3    | Bob    | `accept`                     | Accept the incoming connection request           |
| 4    | Alice  | `ingest file.txt`            | Encrypt a local file into the secure vault       |
| 5    | Alice  | `send bob file.txt`          | Transfer the encrypted file to Bob               |
| 6    | Bob    | `decrypt file.txt new.txt`   | Decrypt the received file to a new path          |
| 7    | Either | `exit`                       | Terminate the session and close the application  |

*Note: This is from Python to Python. Java has similar commands with different names.