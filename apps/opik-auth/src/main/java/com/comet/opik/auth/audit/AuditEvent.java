package com.comet.opik.auth.audit;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

import java.util.List;
import java.util.Map;

/**
 * One row of {@code audit_logs} (shared with opik-backend). Serialised with ClickHouse column names for
 * {@code INSERT ... FORMAT JSONEachRow}. Never put secrets, passwords or request bodies in here.
 */
@Builder(toBuilder = true)
public record AuditEvent(
        @JsonProperty("id") String id,
        @JsonProperty("event_time") String eventTime,
        @JsonProperty("source") String source,
        @JsonProperty("workspace_id") String workspaceId,
        @JsonProperty("workspace_name") String workspaceName,
        @JsonProperty("actor") String actor,
        @JsonProperty("actor_type") String actorType,
        @JsonProperty("credential_id") String credentialId,
        @JsonProperty("action") String action,
        @JsonProperty("outcome") String outcome,
        @JsonProperty("http_method") String httpMethod,
        @JsonProperty("route") String route,
        @JsonProperty("path") String path,
        @JsonProperty("status") int status,
        @JsonProperty("resource_type") String resourceType,
        @JsonProperty("resource_id") String resourceId,
        @JsonProperty("path_params") Map<String, String> pathParams,
        @JsonProperty("required_permissions") List<String> requiredPermissions,
        @JsonProperty("client_ip") String clientIp,
        @JsonProperty("user_agent") String userAgent,
        @JsonProperty("trace_id") String traceId,
        @JsonProperty("duration_ms") long durationMs,
        @JsonProperty("details") String details) {
}
