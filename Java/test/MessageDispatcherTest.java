import org.junit.Test;
import static org.junit.Assert.*;

public class MessageDispatcherTest {

    @Test
    public void testExtractFieldValid() {
        String json = "{\"type\":\"HANDSHAKE_INIT\", \"sender\":\"Bob\"}";
        String result = MessageDispatcher.extractField(json, "sender");
        assertEquals("Bob", result);
    }

    @Test
    public void testExtractFieldMissing() {
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
        String json = "{\"payload\":{\"filename\":\"data.txt\",\"size\":100}}";
        String result = MessageDispatcher.extractPayload(json);
        assertEquals("{\"filename\":\"data.txt\",\"size\":100}", result);
    }

    @Test
    public void testExtractPayloadUnclosed() {
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
        String json = "{\"payload\":\"SGVsbG8gV29ybGQ=\"}";
        String result = MessageDispatcher.extractRawPayload(json);
        assertEquals("SGVsbG8gV29ybGQ=", result);
    }
}