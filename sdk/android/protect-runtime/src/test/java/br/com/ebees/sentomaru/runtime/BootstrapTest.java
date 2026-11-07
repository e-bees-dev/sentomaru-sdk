package br.com.ebees.sentomaru.runtime;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** The provider's decision never throws and refuses everything but a plain https URL with a host. */
public class BootstrapTest {
    private static final String URL = "https://api.example/v1/ebees/exampleapp/prod/installations";

    @Test public void acceptsAValidUrl() {
        assertEquals(URL, Bootstrap.decide(false, () -> URL));
    }

    @Test public void refusesWithoutThrowing() {
        assertNull("exported provider", Bootstrap.decide(true, () -> URL));
        assertNull("meta-data missing", Bootstrap.decide(false, () -> null));
        assertNull("reader throws", Bootstrap.decide(false, () -> { throw new SecurityException("x"); }));
        assertNull("reader errors", Bootstrap.decide(false, () -> { throw new StackOverflowError(); }));
        for (String bad : new String[] {"", "http://api.example/x", "https:///x", "https://user@api.example/x", "https://api.example/a b",
                "https://api.example/\u0000", "https://api.example/\n", "ftp://api.example", "not a url", "https://api.example/" + "a".repeat(2048)}) {
            assertNull(bad, Bootstrap.decide(false, () -> bad));
        }
    }

    @Test public void runtimeStateIsSetOnceAndNeverFromARefusal() {
        SentomaruRuntime.initialize(null);
        SentomaruRuntime.initialize("http://api.example/x");
        assertFalse(SentomaruRuntime.isInitialized());
        assertNull(SentomaruRuntime.enrollmentUrl());
        SentomaruRuntime.initialize(URL);
        SentomaruRuntime.initialize("https://other.example/x");
        assertTrue(SentomaruRuntime.isInitialized());
        assertEquals(URL, SentomaruRuntime.enrollmentUrl());
    }
}
