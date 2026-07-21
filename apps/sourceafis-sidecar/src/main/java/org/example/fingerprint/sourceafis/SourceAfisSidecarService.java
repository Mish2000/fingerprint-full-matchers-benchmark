package org.example.fingerprint.sourceafis;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;

public final class SourceAfisSidecarService implements AutoCloseable {
    private static final int MAX_REQUEST_BYTES = 20 * 1024 * 1024;
    private static final ObjectMapper JSON = new ObjectMapper();
    private final HttpServer server;
    private final SourceAfisEngine engine;
    private final String host;
    private final ExecutorService executor;

    SourceAfisSidecarService(String host, int port) throws IOException {
        InetAddress address = InetAddress.getByName(host);
        if (!address.isLoopbackAddress()) throw new IllegalArgumentException("sidecar host must resolve to loopback");
        this.host = address.getHostAddress();
        this.engine = new SourceAfisEngine(BuildInfo.load());
        this.server = HttpServer.create(new InetSocketAddress(address, port), 0);
        this.executor = Executors.newCachedThreadPool();
        this.server.setExecutor(executor);
        this.server.createContext("/health", exchange -> dispatch(exchange, "GET", () -> engine.health(this.host, port())));
        this.server.createContext("/extract-template", exchange -> dispatch(exchange, "POST", () -> engine.extractTemplate(readRequest(exchange))));
        this.server.createContext("/verify", exchange -> dispatch(exchange, "POST", () -> engine.verify(readRequest(exchange))));
    }

    void start() { server.start(); }
    int port() { return server.getAddress().getPort(); }
    String host() { return host; }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    private void dispatch(HttpExchange exchange, String requiredMethod, Action action) throws IOException {
        try {
            if (!exchange.getHttpContext().getPath().equals(exchange.getRequestURI().getPath())) throw new ApiException(404, "not_found", "route does not exist");
            if (!requiredMethod.equals(exchange.getRequestMethod())) throw new ApiException(405, "method_not_allowed", "HTTP method is not allowed");
            write(exchange, 200, action.run());
        } catch (ApiException exception) {
            write(exchange, exception.status(), error(exception.code(), exception.getMessage()));
        } catch (Exception exception) {
            write(exchange, 500, error("internal_error", "sidecar request failed"));
        } finally {
            exchange.close();
        }
    }

    private static Map<String, Object> readRequest(HttpExchange exchange) {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.toLowerCase().startsWith("application/json")) throw new ApiException(415, "unsupported_media_type", "Content-Type must be application/json");
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int total = 0;
            for (int count; (count = exchange.getRequestBody().read(buffer)) >= 0;) {
                total += count;
                if (total > MAX_REQUEST_BYTES) throw new ApiException(413, "request_too_large", "request body is too large");
                output.write(buffer, 0, count);
            }
            Map<String, Object> request = JSON.readValue(output.toByteArray(), new TypeReference<Map<String, Object>>() {});
            if (request == null) throw new ApiException(400, "invalid_json", "request must be a JSON object");
            return request;
        } catch (ApiException exception) {
            throw exception;
        } catch (IOException | RuntimeException exception) {
            throw new ApiException(400, "invalid_json", "request must be a JSON object");
        }
    }

    private static void write(HttpExchange exchange, int status, Map<String, Object> response) throws IOException {
        byte[] body = JSON.writeValueAsString(response).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }

    private static Map<String, Object> error(String code, String message) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "error");
        response.put("error_code", code);
        response.put("message", message);
        return response;
    }

    @FunctionalInterface
    private interface Action { Map<String, Object> run(); }

    public static void main(String[] args) throws Exception {
        String host = "127.0.0.1";
        int port = 0;
        for (int index = 0; index < args.length; index += 2) {
            if (index + 1 >= args.length) throw new IllegalArgumentException("arguments require values");
            if ("--host".equals(args[index])) host = args[index + 1];
            else if ("--port".equals(args[index])) port = Integer.parseInt(args[index + 1]);
            else throw new IllegalArgumentException("unknown argument: " + args[index]);
        }
        SourceAfisSidecarService service = new SourceAfisSidecarService(host, port);
        Runtime.getRuntime().addShutdownHook(new Thread(service::close));
        service.start();
        System.out.println(JSON.writeValueAsString(Map.of("status", "ready", "host", service.host(), "port", service.port())));
        System.out.flush();
    }
}
