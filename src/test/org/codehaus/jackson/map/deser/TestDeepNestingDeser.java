package org.codehaus.jackson.map.deser;

import java.util.List;
import java.util.Map;

import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.BaseMapTest;
import org.codehaus.jackson.map.DeserializationConfig;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.node.ArrayNode;
import org.codehaus.jackson.node.ObjectNode;

/**
 * Unit tests to verify that deeply nested "untyped" (java.lang.Object)
 * and {@link JsonNode} content is rejected with a {@link JsonParseException}
 * instead of overflowing the stack (CVE-2026-95155).
 */
public class TestDeepNestingDeser extends BaseMapTest
{
    private final static int NOT_TOO_DEEP = 1000;

    private final static int TOO_DEEP_NESTING = 1024;

    /**
     * Nesting level that overflows the stack without depth checks.
     */
    private final static int EXPLOIT_NESTING = 100000;

    private final ObjectMapper mapper = new ObjectMapper();

    /*
    /**********************************************************
    /* Untyped (java.lang.Object) content
    /**********************************************************
     */

    public void testTooDeepUntypedWithArray() throws Exception
    {
        _assertTooDeepUntyped(_nestedDoc(TOO_DEEP_NESTING, "[ ", "] "), Object.class);
    }

    public void testTooDeepUntypedWithObject() throws Exception
    {
        _assertTooDeepUntyped("{" + _nestedDoc(TOO_DEEP_NESTING, "\"x\":{", "} ") + "}", Object.class);
    }

    public void testTooDeepUntypedWithJavaArrays() throws Exception
    {
        ObjectMapper m = new ObjectMapper();
        m.configure(DeserializationConfig.Feature.USE_JAVA_ARRAY_FOR_JSON_ARRAY, true);
        try {
            m.readValue(_nestedDoc(TOO_DEEP_NESTING, "[ ", "] "), Object.class);
            fail("Should have thrown an exception.");
        } catch (JsonParseException jpe) {
            _verifyTooDeep(jpe);
        }
        try {
            m.readValue(_nestedDoc(EXPLOIT_NESTING, "[", "]"), Object.class);
            fail("Should have thrown an exception.");
        } catch (JsonParseException jpe) {
            _verifyTooDeep(jpe);
        }
    }

    public void testTooDeepUntypedInMapAndList() throws Exception
    {
        _assertTooDeepUntyped("{\"a\":" + _nestedDoc(TOO_DEEP_NESTING, "[ ", "] ") + "}", Map.class);
        _assertTooDeepUntyped("[" + _nestedDoc(TOO_DEEP_NESTING, "{\"x\":[", "]} ") + "]", List.class);
        _assertTooDeepUntyped("{\"a\":" + _nestedDoc(EXPLOIT_NESTING, "[", "]") + "}", Map.class);
        _assertTooDeepUntyped("[" + _nestedDoc(EXPLOIT_NESTING / 2, "{\"x\":[", "]}") + "]", List.class);
    }

    public void testExploitUntypedWithArray() throws Exception
    {
        _assertTooDeepUntyped(_nestedDoc(EXPLOIT_NESTING, "[", "]"), Object.class);
    }

    public void testExploitUntypedWithObject() throws Exception
    {
        _assertTooDeepUntyped("{" + _nestedDoc(EXPLOIT_NESTING, "\"x\":{", "}") + "}", Object.class);
    }

    public void testNotTooDeepUntypedArray() throws Exception
    {
        final String doc = _nestedDoc(NOT_TOO_DEEP, "[ ", "] ");
        Object ob = mapper.readValue(doc, Object.class);
        assertTrue(ob instanceof List<?>);
    }

    public void testNotTooDeepUntypedObject() throws Exception
    {
        final String doc = "{" + _nestedDoc(NOT_TOO_DEEP, "\"x\":{", "} ") + "}";
        Object ob = mapper.readValue(doc, Object.class);
        assertTrue(ob instanceof Map<?, ?>);
    }

    /*
    /**********************************************************
    /* JsonNode (tree model) content
    /**********************************************************
     */

    public void testTooDeepTreeWithArray() throws Exception
    {
        _assertTooDeepTree(_nestedDoc(TOO_DEEP_NESTING, "[ ", "] "));
    }

    public void testTooDeepTreeWithObject() throws Exception
    {
        _assertTooDeepTree("{" + _nestedDoc(TOO_DEEP_NESTING, "\"x\":{", "} ") + "}");
    }

    public void testTooDeepTreeWithMixed() throws Exception
    {
        _assertTooDeepTree("[" + _nestedDoc(TOO_DEEP_NESTING, "{\"x\":[", "]} ") + "]");
    }

    public void testTooDeepTypedNodes() throws Exception
    {
        try {
            mapper.readValue(_nestedDoc(TOO_DEEP_NESTING, "[ ", "] "), ArrayNode.class);
            fail("Should have thrown an exception.");
        } catch (JsonParseException jpe) {
            _verifyTooDeep(jpe);
        }
        try {
            mapper.readValue("{" + _nestedDoc(TOO_DEEP_NESTING, "\"x\":{", "} ") + "}", ObjectNode.class);
            fail("Should have thrown an exception.");
        } catch (JsonParseException jpe) {
            _verifyTooDeep(jpe);
        }
        try {
            mapper.readValue(_nestedDoc(EXPLOIT_NESTING, "[", "]"), ArrayNode.class);
            fail("Should have thrown an exception.");
        } catch (JsonParseException jpe) {
            _verifyTooDeep(jpe);
        }
        try {
            mapper.readValue("{" + _nestedDoc(EXPLOIT_NESTING, "\"x\":{", "}") + "}", ObjectNode.class);
            fail("Should have thrown an exception.");
        } catch (JsonParseException jpe) {
            _verifyTooDeep(jpe);
        }
    }

    public void testExploitTreeWithMixed() throws Exception
    {
        _assertTooDeepTree("[" + _nestedDoc(EXPLOIT_NESTING / 2, "{\"x\":[", "]}") + "]");
    }

    public void testExploitTreeWithArray() throws Exception
    {
        _assertTooDeepTree(_nestedDoc(EXPLOIT_NESTING, "[", "]"));
    }

    public void testExploitTreeWithObject() throws Exception
    {
        _assertTooDeepTree("{" + _nestedDoc(EXPLOIT_NESTING, "\"x\":{", "}") + "}");
    }

    public void testNotTooDeepTreeArray() throws Exception
    {
        final String doc = _nestedDoc(NOT_TOO_DEEP, "[ ", "] ");
        JsonNode node = mapper.readTree(doc);
        assertTrue(node.isArray());
        node = mapper.readValue(doc, JsonNode.class);
        assertTrue(node.isArray());
    }

    public void testNotTooDeepTreeObject() throws Exception
    {
        final String doc = "{" + _nestedDoc(NOT_TOO_DEEP, "\"x\":{", "} ") + "}";
        JsonNode node = mapper.readTree(doc);
        assertTrue(node.isObject());
        node = mapper.readValue(doc, JsonNode.class);
        assertTrue(node.isObject());
    }

    /*
    /**********************************************************
    /* Helper methods
    /**********************************************************
     */

    private void _assertTooDeepUntyped(String doc, Class<?> type) throws Exception
    {
        try {
            mapper.readValue(doc, type);
            fail("Should have thrown an exception.");
        } catch (JsonParseException jpe) {
            _verifyTooDeep(jpe);
        }
    }

    private void _assertTooDeepTree(String doc) throws Exception
    {
        try {
            mapper.readTree(doc);
            fail("Should have thrown an exception.");
        } catch (JsonParseException jpe) {
            _verifyTooDeep(jpe);
        }
        try {
            mapper.readValue(doc, JsonNode.class);
            fail("Should have thrown an exception.");
        } catch (JsonParseException jpe) {
            _verifyTooDeep(jpe);
        }
    }

    private void _verifyTooDeep(JsonParseException jpe)
    {
        String msg = jpe.getMessage();
        assertTrue("Unexpected message: " + msg, msg.startsWith("JSON is too deeply nested."));
    }

    private String _nestedDoc(int nesting, String open, String close)
    {
        StringBuilder sb = new StringBuilder(nesting * (open.length() + close.length()));
        for (int i = 0; i < nesting; ++i) {
            sb.append(open);
            if ((i & 31) == 0) {
                sb.append("\n");
            }
        }
        for (int i = 0; i < nesting; ++i) {
            sb.append(close);
            if ((i & 31) == 0) {
                sb.append("\n");
            }
        }
        return sb.toString();
    }
}
