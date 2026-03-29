import java.util.Base64;
import java.util.List;
import java.util.ArrayList;
import java.nio.file.Files;
import java.nio.file.Paths;

public class MessageDispatcher {

    private final NetworkManager network;
    private final IdentityManager identity;
    private final String myName;
    private final FileManager fileManager;

    public MessageDispatcher(NetworkManager network, IdentityManager identity, String myName, FileManager fileManager) {
        this.network  = network;
        this.identity = identity;
        this.myName   = myName;
        this.fileManager = fileManager;
    }

    public void handle(String json) {
        try {
            String type   = extractField(json, "type");
            String sender = extractField(json, "sender");

            switch (type) {
                case "HANDSHAKE_INIT":     handleHandshakeInit(sender, json);     break;
                case "HANDSHAKE_RESPONSE": handleHandshakeResponse(sender, json); break;
                case "CHAT_MESSAGE":       handleChatMessage(sender, json);       break;
                case "FILE_LIST_REQUEST":
                    // 1. Get the files from the local shared folder
                    List<String> files = fileManager.listSharedFiles();
    
                    // 2. Format them into a JSON array: "file1.txt", "file2.txt"
                    StringBuilder jsonArray = new StringBuilder("[");
                    for (int i = 0; i < files.size(); i++) {
                        jsonArray.append("\"").append(files.get(i)).append("\"");
                        if (i < files.size() - 1) jsonArray.append(", ");
                    }
                    jsonArray.append("]");

                    // 3. Build the response payload
                    String response = "{\"type\":\"FILE_LIST_RESPONSE\"," +
                                        "\"sender\":\"" + myName + "\"," +
                                        "\"payload\":{\"files\":" + jsonArray.toString() + "}}";

                    // 4. Send it back to the peer
                    String[] peerInfo = PeerDiscovery.activePeers.get(sender);
                    if (peerInfo != null) {
                        network.sendMessage(peerInfo[0], Integer.parseInt(peerInfo[1]), response);
                        System.out.println("[*] Sent file list to " + sender);
                    }
                    break;
                case "FILE_LIST_RESPONSE":
                    handleFileListResponse(sender, json);
                    break;
                case "PUSH_PROPOSAL":
                    // Alice is offering you a file
                    String pushPayload = extractPayload(json);
                    String pushFile = extractField(pushPayload, "filename"); 
                    System.out.println("\n[!] INCOMING FILE OFFER: " + sender + " wants to send you '" + pushFile + "'.");
                    System.out.print("Accept transfer? (y/n) > ");
                    PeerDiscovery.pendingOffers.put(sender, new String[]{pushFile});
                    break;

                case "TRANSFER_REQUEST":
                    // Alice wants to download a file from us
                    String reqPayload = extractPayload(json);
                    String reqFile = extractField(reqPayload, "filename"); 
    
                    // Check if this is a request for a file we JUST offered her
                    if (reqFile.equals(PeerDiscovery.autoApproveFile)) {
                        System.out.println("\n[*] Auto-approving request for '" + reqFile + "' (previously offered).");
                        PeerDiscovery.autoApproveFile = null; // Clear the flag
                        executeApprovedTransfer(sender, reqFile); // Send the file immediately!
                    } else {
                        // Standard pull request
                        System.out.println("\n[!] CONSENT REQUIRED: " + sender + " wants to download '" + reqFile + "' from you.");
                        System.out.print("Allow? (y/n) > ");
                        PeerDiscovery.pendingTransfers.put(sender, new String[]{reqFile});
                    }
                    break;
                case "TRANSFER_ACCEPT":
                    handleTransferAccept(sender, json);
                    break;
                case "OFFER_ACCEPT":
                    handleOfferAccept(sender, json);
                    break;
                case "OFFER_REJECT":
                    System.out.println("\n[-] " + sender + " declined your file offer.");
                    System.out.print(myName + " > ");
                    break;
                case "PEER_LEFT":
                    PeerDiscovery.activePeers.remove(sender);
                    network.removeSession(sender);
                    System.out.println("\n[-] " + sender + " left the network.");
                    System.out.print(myName + " > ");
                    break;
                default:
                    System.out.println("[-] Unknown message type '" + type + "' from " + sender);
            }
        } catch (Exception e) {
            System.out.println("[-] Dispatch error: " + e.getMessage());
        }
    }

    // CHANGED: was reading ephemeral key from mDNS — now reads identity_key and ephemeral_share
    // from the payload, matching Python's HANDSHAKE_INIT field names exactly.
    private void handleHandshakeInit(String sender, String json) {
        try {
            String payload        = extractPayload(json);
            // CHANGED: Python sends "ephemeral_share" not "ephemeral_key"
            byte[] peerEphemeral  = Base64.getDecoder().decode(extractField(payload, "ephemeral_share"));
            byte[] peerSig        = Base64.getDecoder().decode(extractField(payload, "signature"));
            // CHANGED: read identity key from payload instead of mDNS (Python peers don't put it in mDNS)
            byte[] peerIdentityKey = Base64.getDecoder().decode(extractField(payload, "identity_key"));

            if (!identity.verify(peerIdentityKey, peerEphemeral, peerSig)) {
                System.out.println("[-] AUTH FAILURE: invalid signature from " + sender);
                return;
            }

            SessionManager session = new SessionManager();
            session.deriveSharedSecret(peerEphemeral);
            network.storeSession(sender, session);

            byte[] myEphemeral = session.getPublicBytes();
            byte[] mySignature = identity.sign(myEphemeral);

            String[] peerInfo = PeerDiscovery.activePeers.get(sender);
            if (peerInfo == null) {
                System.out.println("[-] Cannot respond to " + sender + " — not in peer table");
                return;
            }

            String response = "{\"type\":\"HANDSHAKE_RESPONSE\"," +
                  "\"sender\":\"" + myName + "\"," +
                  "\"payload\":{" +
                  "\"ephemeral_key\":\""  + Base64.getEncoder().encodeToString(myEphemeral) + "\"," +
                  "\"signature\":\""      + Base64.getEncoder().encodeToString(mySignature) + "\"," +
                  "\"identity_key\":\""   + Base64.getEncoder().encodeToString(identity.getPublicKeyBytes()) + "\"" +
                  "}}";

            network.sendMessage(peerInfo[0], Integer.parseInt(peerInfo[1]), response);
            System.out.println("[+] Handshake complete. Secure session established with " + sender);

        } catch (Exception e) {
            System.out.println("[-] HANDSHAKE_INIT error from " + sender + ": " + e.getMessage());
        }
    }

    private void handleHandshakeResponse(String sender, String json) {
        try {
            SessionManager pendingSession = network.getPendingSession(sender);
            if (pendingSession == null) {
                System.out.println("[-] Unexpected HANDSHAKE_RESPONSE from " + sender + " (no pending session)");
                return;
            }

            String payload        = extractPayload(json);
            byte[] peerEphemeral  = Base64.getDecoder().decode(extractField(payload, "ephemeral_key"));
            byte[] peerSig        = Base64.getDecoder().decode(extractField(payload, "signature"));

            // Verify sig if we have their identity key from mDNS (Java peers expose it; Python peers don't)
            String[] peerInfo = PeerDiscovery.activePeers.get(sender);
            if (peerInfo != null && peerInfo[2] != null) {
                byte[] peerIdentityKey = Base64.getDecoder().decode(peerInfo[2]);
                if (!identity.verify(peerIdentityKey, peerEphemeral, peerSig)) {
                    System.out.println("[-] AUTH FAILURE: invalid signature in HANDSHAKE_RESPONSE from " + sender);
                    network.removePendingSession(sender);
                    return;
                }
            } else {
                System.out.println("[!] WARNING: Identity not verified for " + sender + " (no public key in mDNS) — connection established but unauthenticated.");
            }

            pendingSession.deriveSharedSecret(peerEphemeral);
            network.storeSession(sender, pendingSession);
            network.removePendingSession(sender);

            System.out.println("[+] Handshake complete. Secure session established with " + sender);

        } catch (Exception e) {
            System.out.println("[-] HANDSHAKE_RESPONSE error from " + sender + ": " + e.getMessage());
        }
    }

    // Mirrors Python's process_chat_message() — payload is a bare base64 string, not an object
    private void handleChatMessage(String sender, String json) {
        try {
            SessionManager session = network.getSession(sender);
            if (session == null) {
                System.out.println("[-] CHAT_MESSAGE from " + sender + " but no secure session");
                return;
            }
            // Python puts the base64 blob as a bare string value: "payload":"<base64>"
            String encryptedB64  = extractRawPayload(json);
            byte[] decrypted     = session.decrypt(Base64.getDecoder().decode(encryptedB64));
            System.out.println("\r\033[K[ " + sender + " ]: " + new String(decrypted, "UTF-8"));
            System.out.print(myName + " > ");
        } catch (Exception e) {
            System.out.println("[-] Failed to decrypt chat message from " + sender);
        }
    }

    // -------------------------------------------------------------------------
    // JSON helpers (unchanged from your original)
    // -------------------------------------------------------------------------

    static String extractField(String json, String key) {
        // Try with space (Python's json.dumps default) then without (Java's format)
        String search = "\"" + key + "\": \"";
        int start = json.indexOf(search);
        if (start == -1) {
            search = "\"" + key + "\":\"";
            start = json.indexOf(search);
        }
        if (start == -1) throw new RuntimeException("field '" + key + "' not found in JSON");
        start += search.length();
        int end = json.indexOf("\"", start);
        return json.substring(start, end);
    }

    static String extractPayload(String json) {
        int start = json.indexOf("\"payload\": {");
        if (start == -1) start = json.indexOf("\"payload\":{");
        if (start == -1) throw new RuntimeException("no payload in JSON");
        start = json.indexOf("{", start + 9); // jump to the opening brace
        int depth = 0, i = start;
        while (i < json.length()) {
            if (json.charAt(i) == '{') depth++;
            else if (json.charAt(i) == '}') { if (--depth == 0) break; }
            i++;
        }
        return json.substring(start, i + 1);
    }

    // ADDED: for when payload is a bare string (e.g. CHAT_MESSAGE)
    static String extractRawPayload(String json) {
        // Try with space (Python's json.dumps default) then without (Java's format)
        String search = "\"payload\": \"";
        int start = json.indexOf(search);
        if (start == -1) {
            search = "\"payload\":\"";
            start = json.indexOf(search);
        }
        if (start == -1) throw new RuntimeException("no string payload in JSON");
        start += search.length();
        return json.substring(start, json.indexOf("\"", start));
    }

    private void handleFileListResponse(String sender, String json) {
        try {
            String payload = extractPayload(json);

            //find the JSON array brackets
            int startBracket = payload.indexOf("[");
            int endBracket = payload.lastIndexOf("]");

            if (startBracket == -1 || endBracket == -1 || endBracket < startBracket) {
                System.out.println("[-] Invalid FILE_LIST_RESPONSE from " + sender + ": no valid JSON array");
                return;
            }

            String arrayContent = payload.substring(startBracket + 1, endBracket).trim();
            if (arrayContent.isEmpty()) {
                System.out.println("[*] " + sender + " has no files available.");
                return;
            } else {
                System.out.println("[*] " + sender + " has the following files:");
                String[] files = arrayContent.split(",");
                for (String file : files) {
                    String fileName = file.replaceAll("[\"\\s]", ""); // remove quotes and whitespace
                    if (!fileName.isEmpty()) {
                        System.out.println("    - " + fileName);
                    }
                }
            }
            System.out.print(myName + " > ");
        } catch (Exception e) {
            System.out.println("[-] Failed to process FILE_LIST_RESPONSE from " + sender + ": " + e.getMessage());
        }
    }

    private void handleTransferAccept(String sender, String json) {
        try {
            String payload = extractPayload(json);
            String fileName = extractField(payload, "filename");
            String encodedData = extractField(payload, "data");
            String receivedHash = extractField(payload, "sha256");
            String encodedSig = extractField(payload, "signature");

            SessionManager session = network.getSession(sender);
            byte[] peerIdentityKey = Base64.getDecoder().decode(PeerDiscovery.activePeers.get(sender)[2]);

            //Verify signature
            byte[] signature = Base64.getDecoder().decode(encodedSig);
            if (!identity.verify(peerIdentityKey, receivedHash.getBytes(), signature)) {
                System.out.println("[-] AUTHENTICATION FAILURE: Signature doesn't match for file transfer from " + sender + " for file " + fileName);
                return;
            }

            //decrypt the data
            byte[] encryptedThing = Base64.getDecoder().decode(encodedData);
            byte[] decryptedData = session.decrypt(encryptedThing);

            //verify hash
            String actualHash = org.bouncycastle.util.encoders.Hex.toHexString(
                java.security.MessageDigest.getInstance("SHA-256").digest(decryptedData)
            );

            if (!actualHash.equalsIgnoreCase(receivedHash)) {
                System.out.println("[-] INTEGRITY FAILURE: Hash doesn't match for file transfer from " + sender + " for file " + fileName);
                return;
            }

            //save the file to downloads folder
            fileManager.saveIncomingFile(fileName, decryptedData);
            System.out.println("\n[+] Received and secured file: " + fileName);
        } catch (Exception e) {
            System.out.println("[-] Failed to process TRANSFER_ACCEPT from " + sender + ": " + e.getMessage());
        }
    }

    private void handleOfferAccept(String sender, String json) {
        try {
            String payload = extractPayload(json);
            String fileName = extractField(payload, "filename");
            System.out.println("\n[+] " + sender + " accepted your offer! Encrypting and sending '" + fileName + "'...");

            // 1. Read the file
            java.nio.file.Path filePath = Paths.get("data_" + myName + "/shared/" + fileName);
            byte[] fileData = Files.readAllBytes(filePath);

            // 2. Hash and Sign (Requirement 5 & 11)
            byte[] hashBytes = java.security.MessageDigest.getInstance("SHA-256").digest(fileData);
            String fileHash = org.bouncycastle.util.encoders.Hex.toHexString(hashBytes);
            byte[] signature = identity.sign(fileHash.getBytes("UTF-8"));

            // 3. Encrypt (Requirement 7)
            SessionManager session = network.getSession(sender);
            byte[] encryptedFile = session.encrypt(fileData);

            // 4. Send the data using the TRANSFER_ACCEPT message type
            String[] peerInfo = PeerDiscovery.activePeers.get(sender);
            if (peerInfo != null) {
                String outPayload = "{" +
                    "\"filename\":\"" + fileName + "\"," +
                    "\"data\":\"" + Base64.getEncoder().encodeToString(encryptedFile) + "\"," +
                    "\"sha256\":\"" + fileHash + "\"," +
                    "\"signature\":\"" + Base64.getEncoder().encodeToString(signature) + "\"" +
                "}";
                String msg = "{\"type\":\"TRANSFER_ACCEPT\",\"sender\":\"" + myName + "\",\"payload\":" + outPayload + "}";
            
                network.sendMessage(peerInfo[0], Integer.parseInt(peerInfo[1]), msg);
                System.out.println("[+] File securely sent to " + sender + "!");
                System.out.print(myName + " > ");
            }

        } catch (Exception e) {
            System.out.println("\n[-] Failed to send file after offer accepted: " + e.getMessage());
            System.out.print(myName + " > ");
        }
    }

    public void executeApprovedTransfer(String target, String fileName) {
        try {
            java.nio.file.Path filePath = Paths.get("data_" + myName + "/shared/" + fileName);
            if (!Files.exists(filePath)) {
                System.out.println("[-] Error: File '" + fileName + "' not found.");
                return;
            }
            byte[] fileData = Files.readAllBytes(filePath);

            byte[] hashBytes = java.security.MessageDigest.getInstance("SHA-256").digest(fileData);
            String fileHash = org.bouncycastle.util.encoders.Hex.toHexString(hashBytes);
            byte[] signature = identity.sign(fileHash.getBytes("UTF-8"));

            SessionManager session = network.getSession(target);
            byte[] encryptedFile = session.encrypt(fileData);

            String[] peerInfo = PeerDiscovery.activePeers.get(target);
            if (peerInfo != null) {
                String payload = "{" +
                    "\"filename\":\"" + fileName + "\"," +
                    "\"data\":\"" + Base64.getEncoder().encodeToString(encryptedFile) + "\"," +
                    "\"sha256\":\"" + fileHash + "\"," +
                    "\"signature\":\"" + Base64.getEncoder().encodeToString(signature) + "\"" +
                "}";
                String msg = "{\"type\":\"TRANSFER_ACCEPT\",\"sender\":\"" + myName + "\",\"payload\":" + payload + "}";
            
                network.sendMessage(peerInfo[0], Integer.parseInt(peerInfo[1]), msg);
                System.out.println("[+] File '" + fileName + "' securely sent to " + target + "!");
            }
        } catch (Exception e) {
            System.out.println("[-] Failed to send file: " + e.getMessage());
        }
    }
}