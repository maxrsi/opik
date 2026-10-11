package com.comet.opik.auth.audit;

import com.comet.opik.auth.config.ClickHouseSettings;
import com.comet.opik.auth.domain.ApiError;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Reads {@code audit_logs}. All user input goes through ClickHouse HTTP query parameters ({@code {name:Type}} +
 * {@code param_name=...}); nothing is concatenated into the SQL text.
 */
@Slf4j
public class AuditQueryService {

    public static final int MAX_PAGE_SIZE = 200;
    public static final int MAX_EXPORT_ROWS = 100_000;
    public static final Duration MAX_RANGE = Duration.ofDays(180);

    private static final String COLUMNS = "id, toUnixTimestamp64Milli(event_time) AS event_time_ms, source, "
            + "workspace_name, actor, actor_type, credential_id, action, outcome, http_method, route, path, status, "
            + "resource_type, resource_id, path_params, required_permissions, client_ip, user_agent, trace_id, "
            + "duration_ms, details";

    private final ClickHouseSettings settings;
    private final ObjectMapper mapper;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    public AuditQueryService(ClickHouseSettings settings, ObjectMapper mapper) {
        this.settings = settings;
        this.mapper = mapper;
    }

    @Builder
    public record Criteria(String workspaceId, Instant from, Instant to, String actor, String action,
            String resourceType, String resourceId, String outcome, String source, Integer status) {
    }

    public record Page(int page, int size, long total, List<Map<String, Object>> content) {
    }

    record Query(String where, Map<String, String> params) {
    }

    static Query buildWhere(Criteria c) {
        var clauses = new ArrayList<String>();
        var params = new LinkedHashMap<String, String>();
        clauses.add("workspace_id = {ws:String}");
        params.put("ws", c.workspaceId());
        clauses.add("event_time >= fromUnixTimestamp64Milli({from:Int64})");
        params.put("from", String.valueOf(c.from().toEpochMilli()));
        clauses.add("event_time <= fromUnixTimestamp64Milli({to:Int64})");
        params.put("to", String.valueOf(c.to().toEpochMilli()));
        if (StringUtils.isNotBlank(c.actor())) {
            clauses.add("actor = {actor:String}");
            params.put("actor", c.actor().strip());
        }
        if (StringUtils.isNotBlank(c.action())) {
            clauses.add("startsWith(action, {action:String})");
            params.put("action", c.action().strip());
        }
        if (StringUtils.isNotBlank(c.resourceType())) {
            clauses.add("resource_type = {resourceType:String}");
            params.put("resourceType", c.resourceType().strip());
        }
        if (StringUtils.isNotBlank(c.resourceId())) {
            clauses.add("resource_id = {resourceId:String}");
            params.put("resourceId", c.resourceId().strip());
        }
        if (StringUtils.isNotBlank(c.outcome())) {
            clauses.add("outcome = {outcome:String}");
            params.put("outcome", c.outcome().strip());
        }
        if (StringUtils.isNotBlank(c.source())) {
            clauses.add("source = {source:String}");
            params.put("source", c.source().strip());
        }
        if (c.status() != null) {
            clauses.add("status = {status:UInt16}");
            params.put("status", String.valueOf(c.status()));
        }
        return new Query(String.join(" AND ", clauses), params);
    }

    public Page find(Criteria criteria, int page, int size) {
        ensureEnabled();
        var q = buildWhere(criteria);
        var params = new LinkedHashMap<>(q.params());
        params.put("limit", String.valueOf(size));
        params.put("offset", String.valueOf((long) (page - 1) * size));
        String table = settings.getDatabase() + ".audit_logs";
        JsonNode rows = execute("SELECT " + COLUMNS + " FROM " + table + " WHERE " + q.where()
                + " ORDER BY event_time DESC, id DESC LIMIT {limit:UInt32} OFFSET {offset:UInt64} FORMAT JSON",
                params);
        JsonNode count = execute("SELECT count() AS total FROM " + table + " WHERE " + q.where() + " FORMAT JSON",
                q.params());
        long total = count.path("data").path(0).path("total").asLong();
        List<Map<String, Object>> content = new ArrayList<>();
        for (JsonNode row : rows.path("data")) {
            content.add(toItem(row));
        }
        return new Page(page, size, total, content);
    }

    public InputStream exportCsv(Criteria criteria) {
        ensureEnabled();
        var q = buildWhere(criteria);
        var params = new LinkedHashMap<>(q.params());
        params.put("limit", String.valueOf(MAX_EXPORT_ROWS));
        String sql = "SELECT id, toString(event_time) AS event_time, source, actor, actor_type, action, outcome, "
                + "http_method, route, path, status, resource_type, resource_id, client_ip, user_agent, duration_ms, "
                + "details FROM " + settings.getDatabase() + ".audit_logs WHERE " + q.where()
                + " ORDER BY event_time DESC, id DESC LIMIT {limit:UInt32} FORMAT CSVWithNames";
        try {
            var response = http.send(request(sql, params), HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() / 100 != 2) {
                String err = new String(response.body().readAllBytes(), StandardCharsets.UTF_8);
                throw failure(response.statusCode(), err);
            }
            return response.body();
        } catch (ApiError e) {
            throw e;
        } catch (Exception e) {
            throw new ApiError(502, "Audit storage unavailable");
        }
    }

    private Map<String, Object> toItem(JsonNode row) {
        var item = new LinkedHashMap<String, Object>();
        item.put("id", row.path("id").asText());
        item.put("eventTime", Instant.ofEpochMilli(row.path("event_time_ms").asLong()).toString());
        item.put("source", row.path("source").asText());
        item.put("workspaceName", row.path("workspace_name").asText());
        item.put("actor", row.path("actor").asText());
        item.put("actorType", row.path("actor_type").asText());
        item.put("credentialId", row.path("credential_id").asText());
        item.put("action", row.path("action").asText());
        item.put("outcome", row.path("outcome").asText());
        item.put("httpMethod", row.path("http_method").asText());
        item.put("route", row.path("route").asText());
        item.put("path", row.path("path").asText());
        item.put("status", row.path("status").asInt());
        item.put("resourceType", row.path("resource_type").asText());
        item.put("resourceId", row.path("resource_id").asText());
        item.put("pathParams", mapper.convertValue(row.path("path_params"), Map.class));
        item.put("requiredPermissions", mapper.convertValue(row.path("required_permissions"), List.class));
        item.put("clientIp", row.path("client_ip").asText());
        item.put("userAgent", row.path("user_agent").asText());
        item.put("traceId", row.path("trace_id").asText());
        item.put("durationMs", row.path("duration_ms").asLong());
        item.put("details", row.path("details").asText());
        return item;
    }

    private JsonNode execute(String sql, Map<String, String> params) {
        try {
            var response = http.send(request(sql, params), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                throw failure(response.statusCode(), response.body());
            }
            return mapper.readTree(response.body());
        } catch (ApiError e) {
            throw e;
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            log.warn("Audit query failed", e);
            throw new ApiError(502, "Audit storage unavailable");
        }
    }

    private ApiError failure(int status, String body) {
        log.warn("ClickHouse audit query failed with status {}: {}", status, StringUtils.left(body, 500));
        if (body != null && body.contains("UNKNOWN_TABLE")) {
            return new ApiError(503, "audit_logs table does not exist yet (run opik-backend analytics migrations)");
        }
        return new ApiError(502, "Audit storage query failed");
    }

    private HttpRequest request(String sql, Map<String, String> params) {
        String qs = params.entrySet().stream()
                .map(e -> "param_" + e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        return HttpRequest.newBuilder(URI.create(settings.getUrl() + "/?" + qs))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                        (settings.getUser() + ":" + settings.getPassword()).getBytes(StandardCharsets.UTF_8)))
                .POST(HttpRequest.BodyPublishers.ofString(sql))
                .build();
    }

    private void ensureEnabled() {
        if (!settings.isEnabled()) {
            throw new ApiError(503, "Audit storage (ClickHouse) is not configured for opik-auth");
        }
    }
}
