package org.example.fingerprint.sourceafis;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;

final class SourceAfisSidecarServiceTest {
    @Test
    void exposesOnlyThreeRoutesAndRejectsMalformedInputs() throws Exception {
        try (SourceAfisSidecarService service = new SourceAfisSidecarService("127.0.0.1", 0)) {
            service.start();
            HttpClient client = HttpClient.newHttpClient();
            URI root = URI.create("http://127.0.0.1:" + service.port());
            HttpResponse<String> health = client.send(HttpRequest.newBuilder(root.resolve("/health")).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, health.statusCode());
            assertTrue(health.body().contains("\"sourceafis_version\":\"3.18.1\""));

            assertNotEquals(404, post(client, root.resolve("/extract-template"), "{\"image_base64\":\"AA==\",\"dpi\":500}"));
            assertNotEquals(404, post(client, root.resolve("/verify"), "{\"template_a_base64\":\"AA==\",\"template_b_base64\":\"AA==\"}"));
            assertEquals(404, post(client, root.resolve("/extract-template-raw"), "{}"));
            assertEquals(404, post(client, root.resolve("/extract-final-minutiae"), "{}"));
        }
    }

    private static int post(HttpClient client, URI uri, String body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(uri).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();
        return client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }
}
