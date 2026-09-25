package labs.mindburn.helm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class ErrorModelTest {
    // The kernel pins this body in core/pkg/httperr (TestErrorModelVector).
    @Test
    void readsTheHelmErrorModel() throws Exception {
        byte[] body = Files.readAllBytes(Path.of("../../protocols/specs/errors/error-model-503.json"));
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getResponseHeaders().set("Content-Type", "application/problem+json");
            exchange.sendResponseHeaders(503, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            HelmClient client = new HelmClient("http://127.0.0.1:" + server.getAddress().getPort());
            HelmClient.HelmApiException err = assertThrows(HelmClient.HelmApiException.class, client::health);
            assertEquals(503, err.status);
            assertEquals("emergency-stop fence active", err.getMessage());
            assertEquals("EMERGENCY_STOP_FENCED", err.reasonCode);
            assertEquals("unavailable", err.code);
            assertTrue(err.retryable);
        } finally {
            server.stop(0);
        }
    }
}
