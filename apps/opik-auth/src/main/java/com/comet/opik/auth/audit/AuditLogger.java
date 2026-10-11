package com.comet.opik.auth.audit;

import com.comet.opik.auth.config.ClickHouseSettings;
import com.comet.opik.auth.domain.Tokens;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.dropwizard.lifecycle.Managed;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Asynchronous writer of opik-auth audit events (login/logout/admin actions) into ClickHouse {@code audit_logs}
 * through the HTTP interface. Bounded queue, flushed every second. A failed batch is kept for retry for up to
 * {@link #RETRY_WINDOW} (bounded by the queue capacity) and dropped after that: there is no compliance requirement
 * and the login path must never block on ClickHouse. The retry matters at first start: the table is created by
 * opik-backend's analytics migration {@code 900001_create_audit_logs.sql}, which runs after opik-auth is up, so
 * e.g. the {@code admin.bootstrap} event is written once the backend has migrated.
 */
@Slf4j
public class AuditLogger implements Managed {

    public static final DateTimeFormatter CH_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS")
            .withZone(ZoneOffset.UTC);

    private final ClickHouseSettings settings;
    private final ObjectMapper mapper;
    private final HttpClient http;
    static final Duration RETRY_WINDOW = Duration.ofMinutes(15);
    private static final int CAPACITY = 10_000;

    private final BlockingQueue<AuditEvent> queue = new ArrayBlockingQueue<>(CAPACITY);
    private final List<AuditEvent> retry = new ArrayList<>();
    private ScheduledExecutorService executor;

    public AuditLogger(ClickHouseSettings settings, ObjectMapper mapper) {
        this.settings = settings;
        this.mapper = mapper;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    }

    public void log(AuditEvent event) {
        var completed = event.toBuilder()
                .id(StringUtils.defaultIfBlank(event.id(), Tokens.uuidV7()))
                .eventTime(StringUtils.defaultIfBlank(event.eventTime(), CH_TIME.format(Instant.now())))
                .source("opik-auth")
                .workspaceId(StringUtils.defaultString(event.workspaceId()))
                .workspaceName(StringUtils.defaultString(event.workspaceName()))
                .actor(StringUtils.defaultString(event.actor()))
                .actorType(StringUtils.defaultIfBlank(event.actorType(), "anonymous"))
                .credentialId(StringUtils.defaultString(event.credentialId()))
                .httpMethod(StringUtils.defaultString(event.httpMethod()))
                .route(StringUtils.defaultString(event.route()))
                .path(StringUtils.defaultString(event.path()))
                .resourceType(StringUtils.defaultIfBlank(event.resourceType(), "auth"))
                .resourceId(StringUtils.defaultString(event.resourceId()))
                .pathParams(event.pathParams() == null ? Map.of() : event.pathParams())
                .requiredPermissions(event.requiredPermissions() == null ? List.of() : event.requiredPermissions())
                .clientIp(StringUtils.defaultString(event.clientIp()))
                .userAgent(StringUtils.left(StringUtils.defaultString(event.userAgent()), 512))
                .traceId(StringUtils.defaultString(event.traceId()))
                .details(StringUtils.defaultIfBlank(event.details(), "{}"))
                .build();
        log.info("audit action='{}' outcome='{}' actor='{}' resource='{}'", completed.action(), completed.outcome(),
                completed.actor(), completed.resourceId());
        if (settings.isEnabled() && !queue.offer(completed)) {
            log.warn("Audit queue full, dropping event '{}'", completed.action());
        }
    }

    @Override
    public void start() {
        if (!settings.isEnabled()) {
            log.info("ClickHouse audit sink disabled; auth audit events are only logged");
            return;
        }
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            var t = new Thread(r, "auth-audit-writer");
            t.setDaemon(true);
            return t;
        });
        executor.scheduleWithFixedDelay(this::flush, 1, 1, TimeUnit.SECONDS);
    }

    @Override
    public void stop() {
        if (executor != null) {
            executor.shutdown();
            flush();
        }
    }

    synchronized void flush() {
        List<AuditEvent> batch = new ArrayList<>(retry);
        retry.clear();
        queue.drainTo(batch, 1000);
        if (batch.isEmpty()) {
            return;
        }
        try {
            var body = new StringBuilder();
            for (AuditEvent e : batch) {
                body.append(mapper.writeValueAsString(e)).append('\n');
            }
            String query = "INSERT INTO " + settings.getDatabase() + ".audit_logs FORMAT JSONEachRow";
            var request = HttpRequest.newBuilder(URI.create(settings.getUrl() + "/?query="
                    + URLEncoder.encode(query, StandardCharsets.UTF_8)))
                    .timeout(Duration.ofSeconds(10))
                    .header("Authorization", basicAuth())
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString()))
                    .build();
            var response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                log.warn("Failed to write {} audit events to ClickHouse, status {}: {}", batch.size(),
                        response.statusCode(), StringUtils.left(response.body(), 500));
                keepForRetry(batch);
            }
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.warn("Failed to write {} audit events to ClickHouse: {}", batch.size(), e.toString());
            keepForRetry(batch);
        }
    }

    private void keepForRetry(List<AuditEvent> batch) {
        String oldest = CH_TIME.format(Instant.now().minus(RETRY_WINDOW));
        // CH_TIME is lexicographically ordered, so string comparison works.
        batch.stream()
                .filter(e -> e.eventTime() != null && e.eventTime().compareTo(oldest) >= 0)
                .limit(CAPACITY)
                .forEach(retry::add);
        int dropped = batch.size() - retry.size();
        if (dropped > 0) {
            log.warn("Dropped {} audit events older than {}", dropped, RETRY_WINDOW);
        }
    }

    int pendingRetries() {
        return retry.size();
    }

    String basicAuth() {
        return "Basic " + Base64.getEncoder().encodeToString(
                (settings.getUser() + ":" + settings.getPassword()).getBytes(StandardCharsets.UTF_8));
    }
}
