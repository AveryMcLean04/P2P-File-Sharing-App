import java.util.Base64;

public class MessageDispatcher {

    private final NetworkManager network;
    private final IdentityManager identity;
    private final String myName;

    public MessageDispatcher(NetworkManager network, IdentityManager identity, String myName) {
        this.network  = network;
        this.identity = identity;
        this.myName   = myName;
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
                    System.out.println("[*] FILE_LIST_REQUEST from " + sender + " (not yet implemented)");
                    break;
                case "FILE_LIST_RESPONSE":
                    System.out.println("[*] FILE_LIST_RESPONSE from " + sender + " (not yet implemented)");
                    break;
                case "TRANSFER_REQUEST":
                    System.out.println("[*] TRANSFER_REQUEST from " + sender + " (not yet implemented)");
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
        String search = "\"payload\":\"";
        int start = json.indexOf(search);
        if (start == -1) throw new RuntimeException("no string payload in JSON");
        start += search.length();
        return json.substring(start, json.indexOf("\"", start));
    }
}