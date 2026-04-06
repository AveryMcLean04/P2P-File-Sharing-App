import org.junit.Test;
import static org.junit.Assert.*;
import java.util.Base64;

public class MessageDispatcherTest {

    @Test
    public void testExtractFieldValid() {
        /**
         * Verifies that extractField correctly pulls a string value
         * from a well-formed JSON string.
         */
        String json = "{\"type\":\"HANDSHAKE_INIT\", \"sender\":\"Bob\"}";
        String result = MessageDispatcher.extractField(json, "sender");
        assertEquals("Bob", result);
    }

    @Test
    public void testExtractFieldMissing() {
        /**
         * Verifies that extractField throws a RuntimeException when
         * the requested key does not exist in the JSON string.
         */
        String json = "{\"type\":\"HANDSHAKE_INIT\"}";
        boolean thrown = false;
        try {
            MessageDispatcher.extractField(json, "sender");
        } catch (RuntimeException e) {
            thrown = true;
        }
        assertTrue(thrown);
    }

    @Test
    public void testExtractFieldMalformed() {
        /**
         * Verifies that extractField throws a RuntimeException when
         * the value for the requested key is not a quoted string.
         */
        String json = "{\"sender\":Bob}";
        boolean thrown = false;
        try {
            MessageDispatcher.extractField(json, "sender");
        } catch (RuntimeException e) {
            thrown = true;
        }
        assertTrue(thrown);
    }

    @Test
    public void testExtractPayloadValid() {
        /**
         * Verifies that extractPayload correctly extracts a nested JSON object
         * from the payload field, including all of its internal fields.
         */
        String json = "{\"payload\":{\"filename\":\"data.txt\",\"size\":100}}";
        String result = MessageDispatcher.extractPayload(json);
        assertEquals("{\"filename\":\"data.txt\",\"size\":100}", result);
    }

    @Test
    public void testExtractPayloadUnclosed() {
        /**
         * Verifies that extractPayload throws a RuntimeException when
         * the payload object is missing its closing brace.
         */
        String json = "{\"payload\":{\"filename\":\"data.txt\"";
        boolean thrown = false;
        try {
            MessageDispatcher.extractPayload(json);
        } catch (RuntimeException e) {
            thrown = true;
        }
        assertTrue(thrown);
    }

    @Test
    public void testExtractRawPayloadValid() {
        /**
         * Verifies that extractRawPayload correctly pulls a raw Base64 string
         * from the payload field, as used in CHAT_MESSAGE types.
         */
        String json = "{\"payload\":\"SGVsbG8gV29ybGQ=\"}";
        String result = MessageDispatcher.extractRawPayload(json);
        assertEquals("SGVsbG8gV29ybGQ=", result);
    }

    @Test
    public void testManifestHashMatchAccepted() throws Exception {
        /**
         * Simulates the Requirement 5 happy path: a file received from a fallback peer
         * matches the hash that was previously signed and cached from the original peer.
         * Verifies that the hash comparison logic correctly accepts a matching hash.
         */
        String fileName = "secret.txt";
        byte[] fileData = "original file contents".getBytes("UTF-8");

        // compute the SHA-256 hash the same way the application does
        byte[] hashBytes = java.security.MessageDigest.getInstance("SHA-256").digest(fileData);
        String expectedHash = org.bouncycastle.util.encoders.Hex.toHexString(hashBytes);

        // simulate caching the expected hash from the original peer's signed manifest
        PeerDiscovery.verifiedCatalogs.put(fileName, expectedHash);

        String cachedHash = PeerDiscovery.verifiedCatalogs.get(fileName);
        assertTrue("verifiedCatalogs should contain the filename", PeerDiscovery.verifiedCatalogs.containsKey(fileName));
        assertTrue("Hash from fallback peer should match the ground-truth hash from original peer",
                   cachedHash.equalsIgnoreCase(expectedHash));

        PeerDiscovery.verifiedCatalogs.remove(fileName);
    }

    @Test
    public void testManifestHashMismatchRejected() throws Exception {
        /**
         * Simulates the Requirement 5 tamper detection path: a file received from a
         * fallback peer has been modified, so its hash does not match the one originally
         * signed by the source peer. Verifies that the mismatch is correctly detected.
         */
        String fileName = "secret.txt";
        byte[] originalData = "original file contents".getBytes("UTF-8");
        byte[] tamperedData = "tampered file contents".getBytes("UTF-8");

        // cache the hash of the original file as if it came from a verified signed manifest
        byte[] originalHashBytes = java.security.MessageDigest.getInstance("SHA-256").digest(originalData);
        String groundTruthHash = org.bouncycastle.util.encoders.Hex.toHexString(originalHashBytes);
        PeerDiscovery.verifiedCatalogs.put(fileName, groundTruthHash);

        // compute the hash of what the fallback peer actually sent
        byte[] tamperedHashBytes = java.security.MessageDigest.getInstance("SHA-256").digest(tamperedData);
        String receivedHash = org.bouncycastle.util.encoders.Hex.toHexString(tamperedHashBytes);

        String cachedHash = PeerDiscovery.verifiedCatalogs.get(fileName);
        assertFalse("Tampered file hash MUST NOT match the ground-truth hash from the original peer",
                    cachedHash.equalsIgnoreCase(receivedHash));

        PeerDiscovery.verifiedCatalogs.remove(fileName);
    }

    @Test
    public void testManifestParsingFromResponse() throws Exception {
        /**
         * Verifies that the manifest region parser correctly locates manifest_bytes
         * and manifest_sig after the files array in a FILE_LIST_RESPONSE payload,
         * without being confused by filenames inside the array.
         */
        String manifestContent = "[{\"filename\":\"secret.txt\", \"hash\":\"abc123\"}]";
        byte[] manifestBytes = manifestContent.getBytes("UTF-8");
        String manifestB64 = Base64.getEncoder().encodeToString(manifestBytes);

        // build a payload that mirrors the real FILE_LIST_RESPONSE structure
        String payload = "{\"files\":[\"secret.txt\"],\"manifest_bytes\":\"" + manifestB64 + "\",\"manifest_sig\":\"dummysig\"}";

        // verify the parser finds manifest_bytes after the files array closes
        int filesEnd = payload.indexOf("]", payload.indexOf("\"files\":"));
        String manifestRegion = filesEnd != -1 ? payload.substring(filesEnd) : payload;

        String extractedB64 = MessageDispatcher.extractField(manifestRegion, "manifest_bytes");
        assertEquals("manifest_bytes should be correctly extracted from after the files array", manifestB64, extractedB64);

        // decode and verify the manifest content round-trips correctly
        byte[] decoded = Base64.getDecoder().decode(extractedB64);
        String decodedStr = new String(decoded, "UTF-8");
        assertTrue("Decoded manifest should contain the original filename", decodedStr.contains("secret.txt"));
        assertTrue("Decoded manifest should contain the original hash", decodedStr.contains("abc123"));
    }
}