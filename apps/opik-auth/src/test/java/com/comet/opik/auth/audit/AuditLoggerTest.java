package com.comet.opik.auth.audit;

import com.comet.opik.auth.config.ClickHouseSettings;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class AuditLoggerTest {

    private HttpServer server;
    private final AtomicInteger status = new AtomicInteger(404);
    private final List<String> received = new CopyOnWriteArrayList<>();
    private AuditLogger logger;

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            int code = status.get();
            if (code == 200) {
                body.lines().forEach(received::add);
            }
            byte[] response = (code == 200 ? "" : "Code: 60. DB::Exception: Unknown table").getBytes();
            exchange.sendResponseHeaders(code, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        var settings = new ClickHouseSettings();
        settings.setEnabled(true);
        settings.setUrl("http://127.0.0.1:" + server.getAddress().getPort());
        logger = new AuditLogger(settings, new ObjectMapper());
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    void failedBatchIsRetriedUntilTheTableExists() {
        logger.log(AuditEvent.builder().action("admin.bootstrap").outcome("success").build());
        logger.flush();
        assertThat(received).isEmpty();
        assertThat(logger.pendingRetries()).isEqualTo(1);

        status.set(200);
        logger.log(AuditEvent.builder().action("auth.login").outcome("success").build());
        logger.flush();
        assertThat(received).hasSize(2);
        assertThat(received.get(0)).contains("admin.bootstrap");
        assertThat(received.get(1)).contains("auth.login");
        assertThat(logger.pendingRetries()).isZero();
    }

    @Test
    void eventsOlderThanTheRetryWindowAreDropped() {
        String old = AuditLogger.CH_TIME.format(Instant.now().minus(AuditLogger.RETRY_WINDOW).minusSeconds(60));
        logger.log(AuditEvent.builder().action("auth.login").outcome("success").eventTime(old).build());
        logger.flush();
        assertThat(logger.pendingRetries()).isZero();
    }
}
