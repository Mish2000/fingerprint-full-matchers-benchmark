package org.example.fingerprint.sourceafis;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

final class SourceAfisEngineTest {
    private final SourceAfisEngine engine = new SourceAfisEngine(BuildInfo.load());

    @Test
    void healthReportsPinnedNarrowRuntime() {
        Map<String, Object> health = engine.health("127.0.0.1", 1234);
        assertEquals("3.18.1", health.get("sourceafis_version"));
        assertEquals("sourceafis-sidecar-contract-v1", health.get("contract_version"));
        assertEquals("none", health.get("thresholding"));
        assertEquals(false, health.get("identification_supported"));
        assertEquals(2, ((java.util.List<?>) health.get("supported_operations")).size());
    }

    @Test
    void extractionRejectsInvalidDpi() {
        ApiException error = assertThrows(ApiException.class, () -> engine.extractTemplate(Map.of("image_base64", "AA==", "dpi", 500)));
        assertEquals("invalid_dpi", error.code());
    }

    @Test
    void extractionRejectsInvalidBase64() {
        ApiException error = assertThrows(ApiException.class, () -> engine.extractTemplate(Map.of("image_base64", "***", "dpi", 1000)));
        assertEquals("invalid_base64", error.code());
    }

    @Test
    void extractionRejectsInvalidEncodedImage() {
        String value = Base64.getEncoder().encodeToString("not-an-image".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        ApiException error = assertThrows(ApiException.class, () -> engine.extractTemplate(Map.of("image_base64", value, "dpi", 1000)));
        assertEquals("invalid_encoded_image", error.code());
    }

    @Test
    void verificationRejectsInvalidTemplate() {
        ApiException error = assertThrows(ApiException.class, () -> engine.verify(Map.of("template_a_base64", "AA==", "template_b_base64", "AA==")));
        assertEquals("invalid_serialized_template", error.code());
    }
}
