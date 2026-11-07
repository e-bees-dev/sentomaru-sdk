package br.com.ebees.sentomaru.sdk.transport;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import br.com.ebees.sentomaru.core.SentomaruException;
import br.com.ebees.sentomaru.sdk.EnrollmentChallenge;
import br.com.ebees.sentomaru.sdk.EnrollmentGrant;
import br.com.ebees.sentomaru.sdk.SentomaruClient;
import br.com.ebees.sentomaru.sdk.SentomaruConfig;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * S2: the HttpURLConnection transport as a Java app calls it (no Kotlin at the call site): one route table built once,
 * one {@code SentomaruUrlConnection.send(...)} per call, typed {@link SentomaruException} catchable from Java.
 */
public class UrlConnectionJavaTest {
    private static final String SESSION = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    private static final String KEY_ID = "11111111-2222-4333-8444-555555555555";

    private MockWebServer server;
    private SentomaruClient client;
    private SentomaruRoutes routes;

    /** Test TLS only; a production app uses the default opener (or its own, for timeouts and pinning). */
    private final SentomaruUrlConnection.Opener opener = url -> {
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        if (connection instanceof HttpsURLConnection) {
            ((HttpsURLConnection) connection).setSSLSocketFactory(TestTls.INSTANCE.getSslContext().getSocketFactory());
            ((HttpsURLConnection) connection).setHostnameVerifier((host, session) -> true);
        }
        return connection;
    };

    @Before
    public void setUp() throws Exception {
        server = new MockWebServer();
        server.useHttps(TestTls.INSTANCE.getSslContext().getSocketFactory(), false);
        server.start();
        String host = server.getHostName();
        Instant now = Instant.parse("2026-10-09T10:00:00Z");
        SentomaruConfig config = new SentomaruConfig("org", "app", "hml", new HashSet<>(Collections.singletonList(host)),
                "https://" + host + ":" + server.getPort() + "/enroll", Duration.ofDays(7), null, null);
        client = new SentomaruClient(config, new TestJcaKeys(), new TestStore(), Clock.fixed(now, ZoneOffset.UTC), null, null);
        byte[] token = new byte[32];
        Arrays.fill(token, (byte) 1);
        byte[] attestation = new byte[32];
        Arrays.fill(attestation, (byte) 2);
        client.enroll(new EnrollmentChallenge(KEY_ID, Base64.getEncoder().encodeToString(token), attestation, now.plusSeconds(300)),
                false, false, signed -> new EnrollmentGrant(SESSION, KEY_ID, SESSION, "hardware", "verified", null, null));
        routes = SentomaruRoutes.of(Collections.singletonList(host),
                Collections.singletonList(new SentomaruRoutes.Route("/v1/pedidos/*", "concluir_pedido")));
    }

    @After
    public void tearDown() throws IOException {
        server.shutdown();
    }

    @Test
    public void aJavaCallerSignsARouteAndReadsTheAnswer() throws Exception {
        server.enqueue(new MockResponse().setResponseCode(200).setBody("{\"ok\":true}"));
        URL url = new URL("https://" + server.getHostName() + ":" + server.getPort() + "/v1/pedidos/42");
        byte[] body = "{\"total\":10}".getBytes(StandardCharsets.UTF_8);
        Map<String, String> headers = Collections.singletonMap("Authorization", "Bearer user-token");

        HttpURLConnection connection = SentomaruUrlConnection.send(client, routes, "POST", url, body, headers, null, opener);
        assertEquals(200, connection.getResponseCode());
        try (InputStream in = connection.getInputStream()) {
            assertEquals("{\"ok\":true}", new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }

        RecordedRequest recorded = server.takeRequest();
        assertEquals("concluir_pedido", recorded.getHeader("x-sentomaru-operation"));
        assertNotNull(recorded.getHeader("signature"));
        assertEquals("Bearer user-token", recorded.getHeader("Authorization"));
    }

    @Test
    public void aJavaCallerCatchesTheTypedRefusal() throws IOException {
        URL url = new URL("http://" + server.getHostName() + ":" + server.getPort() + "/v1/pedidos/42");
        try {
            SentomaruUrlConnection.send(client, routes, "POST", url, new byte[0], Collections.emptyMap());
            fail("http to an allowed host was sent");
        } catch (SentomaruException e) {
            assertEquals("HostNotAllowed", e.getError().getCode());
        }
        assertEquals(0, server.getRequestCount());
    }
}
