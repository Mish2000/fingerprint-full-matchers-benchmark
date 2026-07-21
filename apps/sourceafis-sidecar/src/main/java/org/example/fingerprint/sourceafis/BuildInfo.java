package org.example.fingerprint.sourceafis;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

final class BuildInfo {
    private final Properties properties;

    private BuildInfo(Properties properties) { this.properties = properties; }

    static BuildInfo load() {
        Properties properties = new Properties();
        try (InputStream input = BuildInfo.class.getResourceAsStream("/sourceafis-sidecar.properties")) {
            if (input == null) throw new IllegalStateException("build properties are missing");
            properties.load(input);
        } catch (IOException exception) {
            throw new IllegalStateException("cannot read build properties", exception);
        }
        return new BuildInfo(properties);
    }

    String sourceAfisVersion() { return required("sourceafis.version"); }
    String sourceAfisCoordinates() { return required("sourceafis.maven.coordinates"); }
    String contractVersion() { return required("sidecar.contract.version"); }
    String implementationVersion() { return required("sidecar.implementation.version"); }

    private String required(String key) {
        String value = properties.getProperty(key);
        if (value == null || value.isBlank() || value.contains("${")) throw new IllegalStateException("missing build property " + key);
        return value.trim();
    }
}
