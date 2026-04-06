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
- **Algorithm:** AES-256-GCM.
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

## Common Commands

The following are some of the most commonly used commands:

### Python

| Step | User   | Command                      | Description                                      |
|------|--------|------------------------------|--------------------------------------------------|
| 1    | Alice  | `help`                       | Show all available commands                      |
| 2    | Alice  | `list`                       | Discover peers on the local network              |
| 3    | Alice  | `connect Bob`                | Initiate secure handshake with Bob               |
| 4    | Bob    | `chat Alice`                 | Send an encrypted message                        |
| 5    | Alice  | `ingest file.txt`            | Encrypt a local file into the secure vault       |
| 6    | Bob    | `find file.txt`              | Search for redundant file copies                 |
| 7    | Alice  | `send Bob file.txt`          | Transfer the encrypted file to Bob               |
| 8    | Bob    | `accept`                     | Accept a pending file transfer                   |
| 9    | Bob    | `vault`                      | List locally secured files                       |
| 10   | Bob    | `decrypt file.txt new.txt`   | Decrypt the received file to a new path          |
| 11   | Bob    | `uningest file.txt`          | Remove a file from Vault                         |
| 12   | Alice  | `migrate`                    | Migrate identity keys                            |
| 13   | Bob    | `test`                       | Run system diagnostics and test suite            |
| 14   | Either | `exit`                       | Terminate the session and close the application  |


### Java
| Step | User   | Command                      | Description                                      |
|------|--------|------------------------------|--------------------------------------------------|
| 1    | Alice  | `list`                       | Discover peers on the local network              |
| 2    | Alice  | `connect Bob`                | Initiate secure handshake with Bob               |
| 3    | Bob    | `chat Alice`                 | Send an encrypted message                        |
| 4    | Alice  | `import`                     | Move files from the local staging folder into the encrypted Vault |
| 5    | Bob    | `fetch Alice`                | Request Alice's shared file list manifest        |
| 6    | Bob    | `request Alice file.txt`     | Request to download a specific file from Alice   |
| 7    | Alice  | `y` (or `yes`)               | Approve the pending file transfer request        |
| 8    | Alice  | `send Bob file.txt`          | Proactively offer a file to Bob                  |
| 9    | Bob    | `y` (or `yes`)               | Accept the proactively offered file from Alice   |
| 10   | Alice  | `migrate`                    | Migrate identity keys to a new keypair           |
| 11   | Either | `exit`                       | Terminate the session and close the application  |


## Sample Workflow 

To easily test the cross-language functionality between the Python and Java clients on the same machine, open two separate terminal windows and follow this workflow.

Terminal 1: Start the Python Client
cd python_client
python main.py Alice_Py 5001
(Set a master password when prompted)

Terminal 2: Start the Java Client
cd java_client
.\run.bat Bob_Java 5002
(Set a master password when prompted)

Step 1 | Alice (Python) : list
Expected result: should discover Bob on the local network

Step 2 | Alice (Python): connect Bob_Java
Expected result: should show secure session established with Bob

Step 3 | Bob (Java): chat Alice_Py
Expected result: Bob should be prompted to enter a message, and it should appear in Alice's terminal

Step 4 | Bob (Java): import
(requires user to make a file in the staging folder)
Expected result: Bob's file should be encrypted into the vault and moved to the shared folder while being removed from the staging directory

Step 5 | Alice (Python): fetch Bob_Java
Expected result: Alice should see the files that Bob is displaying in his manifest

Step 6 | Bob (Java): send Alice_Py test.txt
Expected result: Alice should be prompted to accept or deny the file transfer

Step 7 | Alice (Python): accept
Expected result: Alice approves the transfer and should be stored in the vault