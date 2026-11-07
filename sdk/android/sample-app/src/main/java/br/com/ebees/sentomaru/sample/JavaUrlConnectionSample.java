package br.com.ebees.sentomaru.sample;

import br.com.ebees.sentomaru.core.SentomaruException;
import br.com.ebees.sentomaru.sdk.SentomaruClient;
import br.com.ebees.sentomaru.sdk.transport.SentomaruRoutes;
import br.com.ebees.sentomaru.sdk.transport.SentomaruUrlConnection;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

/**
 * S2, lab only: how a Java app signs an HttpURLConnection call with the Sentomaru SDK. The route table is the profile's
 * {@code network-signing} section, built once; every protected call is one {@code SentomaruUrlConnection.send}. Kept by
 * {@code proguard-rules.pro} so the minified release build exercises the SDK's {@code -keepnames} rule (the class name
 * {@code sentomaru protect} looks for); it is never run in CI and has no UI.
 */
public final class JavaUrlConnectionSample {
    private final SentomaruClient sentomaru;
    private final SentomaruRoutes routes;

    public JavaUrlConnectionSample(SentomaruClient sentomaru, String host) {
        this.sentomaru = sentomaru;
        // guide:begin urlconnection-routes
        this.routes = SentomaruRoutes.of(Collections.singletonList(host),
                Collections.singletonList(new SentomaruRoutes.Route("/v1/pedidos/*", "concluir_pedido")));
        // guide:end urlconnection-routes
    }

    /** Sends {@code json} to {@code url}; returns the status, or -1 when the SDK refused to send it. */
    public int conclude(URL url, String json, String bearer) throws IOException {
        // guide:begin urlconnection-send
        try {
            HttpURLConnection connection = SentomaruUrlConnection.send(sentomaru, routes, "POST", url,
                    json.getBytes(StandardCharsets.UTF_8), Collections.singletonMap("Authorization", "Bearer " + bearer));
            int status = connection.getResponseCode();
            InputStream body = status < 400 ? connection.getInputStream() : connection.getErrorStream();
            if (body != null) body.close();
            return status;
        } catch (SentomaruException refused) {
            return -1; // typed: HostNotAllowed, NotEnrolled, BodyTooLarge, InvalidRequest:...
        }
        // guide:end urlconnection-send
    }
}
