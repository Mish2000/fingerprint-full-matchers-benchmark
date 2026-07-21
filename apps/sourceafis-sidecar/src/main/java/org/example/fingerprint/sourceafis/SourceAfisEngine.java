package org.example.fingerprint.sourceafis;

import com.machinezoo.sourceafis.FingerprintImage;
import com.machinezoo.sourceafis.FingerprintImageOptions;
import com.machinezoo.sourceafis.FingerprintMatcher;
import com.machinezoo.sourceafis.FingerprintTemplate;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class SourceAfisEngine {
    static final String TEMPLATE_FORMAT = "sourceafis";
    private final BuildInfo build;

    SourceAfisEngine(BuildInfo build) { this.build = build; }

    Map<String, Object> health(String host, int port) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "ok");
        response.put("service", "sourceafis-sidecar");
        response.put("method_id", "sourceafis");
        response.put("implementation_version", build.implementationVersion());
        response.put("contract_version", build.contractVersion());
        response.put("sourceafis_version", build.sourceAfisVersion());
        response.put("sourceafis_maven_coordinates", build.sourceAfisCoordinates());
        response.put("template_format", TEMPLATE_FORMAT);
        response.put("template_version", build.sourceAfisVersion());
        response.put("java_runtime_version", System.getProperty("java.runtime.version"));
        response.put("transport", "loopback-http-json");
        response.put("bind_host", host);
        response.put("bind_port", port);
        response.put("dpi_policy", "explicit_manifest_nominal_ppi_1000_or_2000");
        response.put("external_preprocessing", "none");
        response.put("decision_logic", "none");
        response.put("thresholding", "none");
        response.put("template_cache", false);
        response.put("identification_supported", false);
        response.put("supported_operations", List.of("template_extraction", "pairwise_verification"));
        response.put("timing_scopes", Map.of(
            "extract_template", "official image construction, template extraction, and serialization",
            "verify", "official template deserialization, matcher construction, and match"
        ));
        return response;
    }

    Map<String, Object> extractTemplate(Map<String, Object> request) {
        byte[] image = decode(request.get("image_base64"), "image_base64");
        int dpi = requiredDpi(request.get("dpi"));
        try {
            long started = System.nanoTime();
            FingerprintImageOptions options = new FingerprintImageOptions().dpi(dpi);
            FingerprintTemplate template = new FingerprintTemplate(new FingerprintImage(image, options));
            byte[] serialized = template.toByteArray();
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("template_base64", Base64.getEncoder().encodeToString(serialized));
            response.put("template_format", TEMPLATE_FORMAT);
            response.put("template_version", build.sourceAfisVersion());
            response.put("elapsed_ms", elapsed(started));
            return response;
        } catch (RuntimeException exception) {
            throw new ApiException(422, "invalid_encoded_image", "image bytes are not a supported encoded fingerprint image");
        }
    }

    Map<String, Object> verify(Map<String, Object> request) {
        byte[] encodedA = decode(request.get("template_a_base64"), "template_a_base64");
        byte[] encodedB = decode(request.get("template_b_base64"), "template_b_base64");
        long started = System.nanoTime();
        try {
            FingerprintTemplate templateA = new FingerprintTemplate(encodedA);
            FingerprintTemplate templateB = new FingerprintTemplate(encodedB);
            double score = new FingerprintMatcher(templateA).match(templateB);
            if (!Double.isFinite(score)) throw new ApiException(500, "non_finite_score", "SourceAFIS returned a non-finite score");
            return Map.of("raw_score", score, "elapsed_ms", elapsed(started));
        } catch (ApiException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new ApiException(422, "invalid_serialized_template", "template bytes are not valid SourceAFIS templates");
        }
    }

    private static byte[] decode(Object value, String field) {
        if (!(value instanceof String) || ((String) value).isEmpty()) throw new ApiException(400, "missing_field", field + " is required");
        try {
            byte[] decoded = Base64.getDecoder().decode((String) value);
            if (decoded.length == 0) throw new IllegalArgumentException();
            return decoded;
        } catch (IllegalArgumentException exception) {
            throw new ApiException(400, "invalid_base64", field + " must contain non-empty Base64");
        }
    }

    private static int requiredDpi(Object value) {
        if (!(value instanceof Number)) throw new ApiException(400, "invalid_dpi", "dpi must be 1000 or 2000");
        double numeric = ((Number) value).doubleValue();
        if ((numeric != 1000.0 && numeric != 2000.0) || numeric != Math.rint(numeric)) throw new ApiException(400, "invalid_dpi", "dpi must be 1000 or 2000");
        return (int) numeric;
    }

    private static double elapsed(long started) { return (System.nanoTime() - started) / 1_000_000.0; }
}
