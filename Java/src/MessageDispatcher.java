import java.util.Base64;
import java.util.List;
import java.util.ArrayList;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * MessageDispatcher is responsible for handling incoming JSON messages
 * from peers, parsing them, and routing them to the appropriate handlers,
 * based on the message type.
 */

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
        /**
         * Main entry point for all incoming network data.
         * Extracts the message type and sender, then uses a switch 
         * statement to trigger the appropriate logic.
         */
        try {
            String type   = extractField(json, "type");
            String sender = extractField(json, "sender");

            switch (type) {
                case "HANDSHAKE_INIT":     handleHandshakeInit(sender, json);     break;
                case "HANDSHAKE_RESPONSE": handleHandshakeResponse(sender, json); break;
                case "CHAT_MESSAGE":       handleChatMessage(sender, json);       break;
                case "FILE_LIST_REQUEST":
                    /**
                     * Generates a JSON array of shared files, creates a manifest with hashes,
                     * signs it for offline verification (Req 5), and sends it to the requester.
                     */
                    List<String> files = fileManager.listSharedFiles();
                    StringBuilder jsonArray = new StringBuilder("[");
                    StringBuilder manifestBuilder = new StringBuilder("[");

                    for (int i = 0; i < files.size(); i++) {
                        String fName = files.get(i);
                        jsonArray.append("\"").append(fName).append("\"");
                        
                        // Get file hash for the manifest
                        String fHash = "";
                        try {
                            java.nio.file.Path fPath = java.nio.file.Paths.get("data_" + myName + "/shared/" + fName);
                            byte[] fData = java.nio.file.Files.readAllBytes(fPath);
                            byte[] hBytes = java.security.MessageDigest.getInstance("SHA-256").digest(fData);
                            fHash = org.bouncycastle.util.encoders.Hex.toHexString(hBytes);
                        } catch (Exception e) {
                            // ignore missing file for manifest hash
                        }

                        manifestBuilder.append("{\"filename\":\"").append(fName).append("\", \"hash\":\"").append(fHash).append("\"}");

                        if (i < files.size() - 1) {
                            jsonArray.append(", ");
                            manifestBuilder.append(", ");
                        }
                    }
                    jsonArray.append("]");
                    manifestBuilder.append("]");

                    try {
                        byte[] manifestBytes = manifestBuilder.toString().getBytes("UTF-8");
                        byte[] manifestSig = identity.sign(manifestBytes);

                        String response = "{\"type\":\"FILE_LIST_RESPONSE\"," +
                                            "\"sender\":\"" + myName + "\"," +
                                            "\"payload\":{" +
                                            "\"files\":" + jsonArray.toString() + "," +
                                            "\"manifest_bytes\":\"" + Base64.getEncoder().encodeToString(manifestBytes) + "\"," +
                                            "\"manifest_sig\":\"" + Base64.getEncoder().encodeToString(manifestSig) + "\"" +
                                            "}}";

                        String[] peerInfo = PeerDiscovery.activePeers.get(sender);
                        if (peerInfo != null) {
                            network.sendMessage(peerInfo[0], Integer.parseInt(peerInfo[1]), response);
                        }
                    } catch (Exception e) {
                        System.out.println("[ERROR] Failed to send file list: " + e.getMessage());
                    }
                    break;
                case "FILE_LIST_RESPONSE":
                    handleFileListResponse(sender, json);
                    break;
                case "PUSH_PROPOSAL":
                    // Handles a peer offering to send us a file
                    String pushPayload = extractPayload(json);
                    String pushFile = extractField(pushPayload, "filename"); 
                    System.out.print("\r\033[K\n\007[!PROPOSAL] " + sender + " wants to SEND you: " + pushFile + "\nAction required: Type 'yes' or 'no'\n" + myName + " > ");
                    PeerDiscovery.pendingOffers.put(sender, new String[]{pushFile});
                    break;
                case "TRANSFER_REQUEST":
                    // Handles a peer asking to download one of our files
                    String reqPayload = extractPayload(json);
                    String reqFile = extractField(reqPayload, "filename"); 
    
                    if (reqFile.equals(PeerDiscovery.autoApproveFile)) {
                        System.out.println("\r\033[K[TRANSFER] Auto-approving download of '" + reqFile + "' for " + sender + ".");
                        System.out.print(myName + " > ");
                        PeerDiscovery.autoApproveFile = null;
                        executeApprovedTransfer(sender, reqFile);
                    } else {
                        System.out.print("\r\033[K\n\007[!REQUEST] " + sender + " wants to DOWNLOAD: " + reqFile + "\nAction required: Type 'yes' or 'no'\n" + myName + " > ");
                        PeerDiscovery.pendingTransfers.put(sender, new String[]{reqFile});
                    }
                    break;
                case "TRANSFER_ACCEPT":
                    handleTransferAccept(sender, json);
                    break;
                case "OFFER_ACCEPT":
                    handleOfferAccept(sender, json);
                    break;
                case "KEY_MIGRATION_NOTIFY":
                    handleKeyMigration(sender, json);
                    break;
                case "OFFER_REJECT":
                case "TRANSFER_REJECT":
                    System.out.print("\r\033[K[SYSTEM] " + sender + " denied your file offer.\n" + myName + " > ");
                    break;
                case "PEER_LEFT":
                    handlePeerLeft(sender);
                    break;
                default:
                    System.out.println("\r\033[K[NETWORK] Unknown message type '" + type + "' from " + sender + "\n" + myName + " > ");
            }
        } catch (Exception e) {
            System.out.println("\r\033[K[ERROR] Dispatch error: " + e.getMessage() + "\n" + myName + " > ");
        }
    }

    private void handleHandshakeInit(String sender, String json) {
        /**
         * Processes the first step of a secure connection. 
         * Verifies the sender's identity signature and saves it to the peer table,
         * then sends back our own ephemeral key and identity signature.
         */
        try {
            String payload        = extractPayload(json);
            byte[] peerEphemeral  = Base64.getDecoder().decode(extractField(payload, "ephemeral_share"));
            byte[] peerSig        = Base64.getDecoder().decode(extractField(payload, "signature"));
            byte[] peerIdentityKey = Base64.getDecoder().decode(extractField(payload, "identity_key"));

            if (!identity.verify(peerIdentityKey, peerEphemeral, peerSig)) {
                System.out.print("\r\033[K[SECURITY] Handshake signature spoofing detected from " + sender + "!\n" + myName + " > ");
                return;
            }

            String[] peerInfo = PeerDiscovery.activePeers.get(sender);
            if (peerInfo != null) {
                peerInfo[2] = Base64.getEncoder().encodeToString(peerIdentityKey);
                PeerDiscovery.activePeers.put(sender, peerInfo);
            } else {
                System.out.print("\r\033[K[ERROR] Cannot respond to " + sender + " — not in peer table\n" + myName + " > ");
                return;
            }

            SessionManager session = new SessionManager();
            session.deriveSharedSecret(peerEphemeral);
            network.storeSession(sender, session);

            byte[] myEphemeral = session.getPublicBytes();
            byte[] mySignature = identity.sign(myEphemeral);

            String response = "{\"type\":\"HANDSHAKE_RESPONSE\"," +
                  "\"sender\":\"" + myName + "\"," +
                  "\"payload\":{" +
                  "\"ephemeral_key\":\""  + Base64.getEncoder().encodeToString(myEphemeral) + "\"," +
                  "\"signature\":\""      + Base64.getEncoder().encodeToString(mySignature) + "\"," +
                  "\"identity_key\":\""   + Base64.getEncoder().encodeToString(identity.getPublicKeyBytes()) + "\"" +
                  "}}";

            network.sendMessage(peerInfo[0], Integer.parseInt(peerInfo[1]), response);
            System.out.print("\r\033[K[SECURITY] Secure session established with " + sender + ".\n" + myName + " > ");

        } catch (Exception e) {
            System.out.print("\r\033[K[ERROR] Handshake Init Failed: " + e.getMessage() + "\n" + myName + " > ");
        }
    }

    private void handleHandshakeResponse(String sender, String json) {
        /**
         * Completes the handshake initiated by this node and saves the peer's 
         * long-term identity key for later manifest verification (Req 5).
         */
        try {
            SessionManager pendingSession = network.getPendingSession(sender);
            if (pendingSession == null) {
                System.out.print("\r\033[K[ERROR] Unexpected HANDSHAKE_RESPONSE from " + sender + " (no pending session)\n" + myName + " > ");
                return;
            }

            String payload        = extractPayload(json);
            byte[] peerEphemeral  = Base64.getDecoder().decode(extractField(payload, "ephemeral_key"));
            byte[] peerSig        = Base64.getDecoder().decode(extractField(payload, "signature"));
            byte[] peerIdentityKey = Base64.getDecoder().decode(extractField(payload, "identity_key"));

            String[] peerInfo = PeerDiscovery.activePeers.get(sender);
            if (peerInfo != null) {
                peerInfo[2] = Base64.getEncoder().encodeToString(peerIdentityKey);
                PeerDiscovery.activePeers.put(sender, peerInfo);
                
                if (!identity.verify(peerIdentityKey, peerEphemeral, peerSig)) {
                    System.out.print("\r\033[K[SECURITY] Invalid identity signature from " + sender + "!\n" + myName + " > ");
                    network.removePendingSession(sender);
                    return;
                }
            }

            pendingSession.deriveSharedSecret(peerEphemeral);
            network.storeSession(sender, pendingSession);
            network.removePendingSession(sender);

            System.out.print("\r\033[K[SECURITY] Mutual trust established with " + sender + ".\n" + myName + " > ");
        } catch (Exception e) {
            System.out.print("\r\033[K[ERROR] Handshake Response Failed: " + e.getMessage() + "\n" + myName + " > ");
        }
    }

    private void handleChatMessage(String sender, String json) {
        /**
         * Decrypts and displays an incoming chat message.
         * Requires an established secure session to proceed.
         */
        try {
            SessionManager session = network.getSession(sender);
            if (session == null) {
                System.out.print("\r\033[K[SECURITY] Blocked CHAT_MESSAGE from " + sender + ": Secure session required.\n" + myName + " > ");
                return;
            }
            String encryptedB64  = extractRawPayload(json);
            byte[] decrypted     = session.decrypt(Base64.getDecoder().decode(encryptedB64));
            System.out.print("\r\033[K[CHAT] " + sender + ": " + new String(decrypted, "UTF-8") + "\n" + myName + " > ");
        } catch (Exception e) {
            System.out.print("\r\033[K[ERROR] Failed to decrypt message from " + sender + ".\n" + myName + " > ");
        }
    }

    private void handleFileListResponse(String sender, String json) {
        /**
         * Parses the JSON array of files offered by a peer, verifies the signed 
         * manifest for offline redundancy (Req 5), and prints the files to the console.
         */
        try {
            String payload = extractPayload(json);

            try {
                // Search for the manifest fields after the files array closes to avoid the
                // hand-made parser getting confused by filenames inside the array
                int filesEnd = payload.indexOf("]", payload.indexOf("\"files\":"));
                String manifestRegion = filesEnd != -1 ? payload.substring(filesEnd) : payload;
                String manifestB64 = extractField(manifestRegion, "manifest_bytes");
                String sigB64 = extractField(manifestRegion, "manifest_sig");
                
                if (!manifestB64.isEmpty() && !sigB64.isEmpty()) {
                    byte[] manifestBytes = Base64.getDecoder().decode(manifestB64);
                    byte[] signature = Base64.getDecoder().decode(sigB64);
                    
                    String[] pInfo = PeerDiscovery.activePeers.get(sender);
                    if (pInfo != null && pInfo[2] != null) {
                        byte[] peerPubKey = Base64.getDecoder().decode(pInfo[2]);
                        if (identity.verify(peerPubKey, manifestBytes, signature)) {
                            String manifestStr = new String(manifestBytes, "UTF-8");
                            int idx = 0;
                            // Manually parse the JSON array to avoid needing external libraries
                            while ((idx = manifestStr.indexOf("{\"filename\":", idx)) != -1) {
                                int endObj = manifestStr.indexOf("}", idx);
                                if (endObj == -1) break;
                                String obj = manifestStr.substring(idx, endObj + 1);
                                String fName = extractField(obj, "filename");
                                String fHash = extractField(obj, "hash");
                                PeerDiscovery.verifiedCatalogs.put(fName, fHash);
                                System.out.println("\r\033[K[SECURITY] Locked in ground-truth hash for '" + fName + "'");
                                idx = endObj + 1;
                            }
                        } else {
                            System.out.println("\r\033[K[ERROR] CRITICAL: Manifest signature verification FAILED!");
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("\r\033[K[WARNING] Received catalog without a valid signed manifest.");
            }

            // Safely locate the "files" array specifically to avoid the manifest array
            int filesKeyIndex = payload.indexOf("\"files\":");
            if (filesKeyIndex == -1) throw new RuntimeException("Missing 'files' key");
            
            int startBracket = payload.indexOf("[", filesKeyIndex);
            int endBracket = payload.indexOf("]", startBracket);

            if (startBracket == -1 || endBracket == -1 || endBracket < startBracket) {
                System.out.print("\r\033[K[ERROR] Invalid FILE_LIST_RESPONSE from " + sender + "\n" + myName + " > ");
                return;
            }

            String arrayContent = payload.substring(startBracket + 1, endBracket).trim();
            if (arrayContent.isEmpty()) {
                System.out.print("\r\033[K[CATALOG] Peer '" + sender + "' offers 0 files:\n  > (Empty)\n" + myName + " > ");
            } else {
                String[] files = arrayContent.split(",");
                System.out.print("\r\033[K[CATALOG] Peer '" + sender + "' offers " + files.length + " files:\n");
                for (String file : files) {
                    String fileName = file.replaceAll("[\"\\s]", "");
                    if (!fileName.isEmpty()) {
                        System.out.println("  > " + fileName);
                    }
                }
                System.out.print(myName + " > ");
            }
        } catch (Exception e) {
            System.out.print("\r\033[K[ERROR] Failed to process FILE_LIST_RESPONSE from " + sender + ": " + e.getMessage() + "\n" + myName + " > ");
        }
    }

    private void handleTransferAccept(String sender, String json) {
        /**
         * Processes an incoming file transfer. 
         * Verifies the digital signature for identity, decrypts the file data, 
         * and checks the SHA-256 hash to ensure the file wasn't tampered with.
         */
        try {
            String payload = extractPayload(json);
            String fileName = extractField(payload, "filename");
            String encodedData = extractField(payload, "data");
            String receivedHash = extractField(payload, "sha256");
            String encodedSig = extractField(payload, "signature");

            SessionManager session = network.getSession(sender);
            String[] peerData = PeerDiscovery.activePeers.get(sender);
            
            if (peerData == null || peerData[2] == null) {
                System.out.print("\r\033[K[ERROR] Cannot verify transfer from " + sender + " (missing identity key)\n" + myName + " > ");
                return;
            }
            byte[] peerIdentityKey = Base64.getDecoder().decode(peerData[2]);

            // Ensure the file sender is who they claim to be by verifying the signature on the hashed file.
            byte[] signature = Base64.getDecoder().decode(encodedSig);
            if (!identity.verify(peerIdentityKey, receivedHash.getBytes("UTF-8"), signature)) {
                System.out.print("\r\033[K[SECURITY] CRITICAL: Identity signature mismatch on " + fileName + "!\n" + myName + " > ");
                return;
            }

            byte[] encryptedThing = Base64.getDecoder().decode(encodedData);
            byte[] decryptedData = session.decrypt(encryptedThing);

            // Verify the integrity of the file by comparing the received hash with a locally computed hash, using SHA-256.
            String actualHash = org.bouncycastle.util.encoders.Hex.toHexString(
                java.security.MessageDigest.getInstance("SHA-256").digest(decryptedData)
            );

            if (!actualHash.equalsIgnoreCase(receivedHash)) {
                System.out.print("\r\033[K[SECURITY] INTEGRITY ALERT: Hash mismatch for " + fileName + "!\n" + myName + " > ");
                return;
            }

            if (PeerDiscovery.verifiedCatalogs.containsKey(fileName)) {
                String expectedHash = PeerDiscovery.verifiedCatalogs.get(fileName);
                System.out.println("\r\033[K[SECURITY] Verifying origin hash against ground-truth manifest...");
                if (!actualHash.equalsIgnoreCase(expectedHash)) {
                    System.out.print("\r\033[K[SECURITY] ORIGIN TAMPER DETECTED: '" + fileName + "' does not match the original creator's manifest!\n" + myName + " > ");
                    return;
                }
            } else {
                System.out.println("\r\033[K[WARNING] No verified manifest found for '" + fileName + "'. Bypassing origin integrity check!");
            }
            fileManager.saveIncomingFile(fileName, decryptedData);
            System.out.print("\r\033[K[FILE] Securely received and stored: " + fileName + "\n" + myName + " > ");
        } catch (Exception e) {
            System.out.print("\r\033[K[ERROR] Transfer intake failed: " + e.getMessage() + "\n" + myName + " > ");
        }
    }

    private void handleOfferAccept(String sender, String json) {
        /**
         * Triggered when a peer accepts a file we offered.
         * Reads the file, hashes it, signs the hash, and sends the 
         * encrypted data over the network.
         */
        try {
            String payload = extractPayload(json);
            String fileName = extractField(payload, "filename");

            java.nio.file.Path filePath = Paths.get("data_" + myName + "/shared/" + fileName);
            byte[] fileData = Files.readAllBytes(filePath);

            byte[] hashBytes = java.security.MessageDigest.getInstance("SHA-256").digest(fileData);
            String fileHash = org.bouncycastle.util.encoders.Hex.toHexString(hashBytes);
            byte[] signature = identity.sign(fileHash.getBytes("UTF-8"));

            SessionManager session = network.getSession(sender);
            byte[] encryptedFile = session.encrypt(fileData);

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
                System.out.print("\r\033[K[TRANSFER] Transfer complete: '" + fileName + "' sent to " + sender + ".\n" + myName + " > ");
            }

        } catch (Exception e) {
            System.out.print("\r\033[K[ERROR] Transfer execution failed: " + e.getMessage() + "\n" + myName + " > ");
        }
    }

    public void executeApprovedTransfer(String target, String fileName) {
        /**
         * Helper method to bundle, encrypt, and send a file once a 
         * download request has been approved by the user.
         */
        try {
            java.nio.file.Path filePath = Paths.get("data_" + myName + "/shared/" + fileName);
            if (!Files.exists(filePath)) {
                System.out.println("[ERROR] Error: File '" + fileName + "' not found.");
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
                System.out.println("[TRANSFER] Transfer complete: '" + fileName + "' sent to " + target + ".");
            }
        } catch (Exception e) {
            System.out.println("[ERROR] Transfer execution failed: " + e.getMessage());
        }
    }

    private void handleKeyMigration(String sender, String json) {
        /**
         * Handles a peer updating their long-term identity. 
         * Verifies that the new key is signed by the old key to 
         * maintain the chain of trust before updating the peer table.
         */
        try {
            String payload = extractPayload(json);

            // Supports multiple possible field names for the new key
            String newKeyB64 = "";
            if (payload.contains("\"new_identity_key\"")) {
                newKeyB64 = extractField(payload, "new_identity_key");
            } else if (payload.contains("\"new_public_key\"")) {
                newKeyB64 = extractField(payload, "new_public_key");
            } else if (payload.contains("\"identity_key\"")) {
                newKeyB64 = extractField(payload, "identity_key");
            }

            if (newKeyB64.isEmpty()) {
                System.out.print("\r\033[K[ERROR] Migration from " + sender + " missing new key field.\n" + myName + " > ");
                return;
            }

            String sigB64 = "";
            if (payload.contains("\"signature\"")) {
                sigB64 = extractField(payload, "signature");
            } else if (payload.contains("\"sig\"")) {
                sigB64 = extractField(payload, "sig");
            }

            if (sigB64.isEmpty()) {
                System.out.print("\r\033[K[ERROR] Migration from " + sender + " missing signature field.\n" + myName + " > ");
                return;
            }

            byte[] newKeyBytes = Base64.getDecoder().decode(newKeyB64);
            byte[] signatureBytes = Base64.getDecoder().decode(sigB64);

            String[] peerInfo = PeerDiscovery.activePeers.get(sender);
            if (peerInfo == null || peerInfo[2] == null) {
                System.out.print("\r\033[K[ERROR] Migration from unknown peer " + sender + "\n" + myName + " > ");
                return;
            }
            byte[] oldKeyBytes = Base64.getDecoder().decode(peerInfo[2]);

            // Verifies that the new key is signed by the old key.
            if (!identity.verify(oldKeyBytes, newKeyBytes, signatureBytes)) {
                System.out.print("\r\033[K[SECURITY] CRITICAL: Forged migration attempt from " + sender + "!\n" + myName + " > ");
                network.removeSession(sender);
                return;
            }

            peerInfo[2] = newKeyB64;
            PeerDiscovery.activePeers.put(sender, peerInfo);
            
            System.out.print("\r\033[K[SECURITY] KEY MIGRATION SUCCESS: " + sender + " has updated their identity.\n" + myName + " > ");

        } catch (Exception e) {
            System.out.print("\r\033[K[ERROR] Migration processing failed: " + e.getMessage() + "\n" + myName + " > ");
        }
    }

    private void handlePeerLeft(String sender) {
        /**
         * Cleans up local state when a peer explicitly notifies us 
         * that they are disconnecting.
         */
        PeerDiscovery.activePeers.remove(sender);
        network.removeSession(sender);
        System.out.print("\r\033[K[NETWORK] Peer Offline: " + sender + "\n" + myName + " > ");
    }

    static String extractField(String json, String key) {
        /**
         * Manual JSON parser to extract a specific string field 
         * without using external libraries.
         */
        String keyMarker = "\"" + key + "\"";
        int searchFrom = 0;
        while (true) {
            // looking for the key in the JSON string
            int keyIndex = json.indexOf(keyMarker, searchFrom);
            if (keyIndex == -1) throw new RuntimeException("field '" + key + "' not found");
            int afterKey = keyIndex + keyMarker.length();
            int colonCandidate = afterKey;
            // skipping any whitespace after the colon
            while (colonCandidate < json.length() && json.charAt(colonCandidate) == ' ') colonCandidate++;
            if (colonCandidate < json.length() && json.charAt(colonCandidate) == ':') {
                // find the opening quote of the value
                int startQuote = json.indexOf("\"", colonCandidate + 1);
                if (startQuote == -1) throw new RuntimeException("malformed JSON value for " + key);
                int endQuote = startQuote + 1;
                while (endQuote < json.length()) {
                    char c = json.charAt(endQuote);
                    // handle escaped characters
                    if (c == '\\') { endQuote += 2; }
                    else if (c == '\"') { break; }
                    else { endQuote++; }
                }
                if (endQuote >= json.length()) throw new RuntimeException("malformed JSON value for " + key);
                return json.substring(startQuote + 1, endQuote);
            }
            searchFrom = keyIndex + 1;
        }
    }

    static String extractPayload(String json) {
        /**
         * Extracts a nested JSON object from the "payload" field 
         * by tracking opening and closing braces to be sure to capture the
         * entire object, in the case of internal fields.
         */
        int start = json.indexOf("\"payload\"");
        if (start == -1) throw new RuntimeException("no payload found");
        
        int openBrace = json.indexOf("{", start);
        if (openBrace == -1) throw new RuntimeException("payload is not an object");

        int depth = 0;
        for (int i = openBrace; i < json.length(); i++) {
            if (json.charAt(i) == '{') depth++;
            else if (json.charAt(i) == '}') {
                depth--;
                if (depth == 0) return json.substring(openBrace, i + 1);
            }
        }
        throw new RuntimeException("unclosed payload object");
    }

    static String extractRawPayload(String json) {
        /**
         * Extracts the raw string content of a payload field, 
         * typically used the CHAT_MESSAGE type where the payload is 
         * just a string instead of a nested JSON object.
         */
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
}