package com.comet.opik.ext.audit;

import lombok.Builder;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** One audit_logs row. Never carries request bodies, trace content or credentials. */
@Builder(toBuilder = true)
public record AuditEvent(
        String id,
        Instant eventTime,
        String workspaceId,
        String workspaceName,
        String actor,
        String actorType,
        String credentialId,
        String action,
        String outcome,
        String httpMethod,
        String route,
        String path,
        int status,
        String resourceType,
        String resourceId,
        Map<String, String> pathParams,
        List<String> requiredPermissions,
        String clientIp,
        String userAgent,
        String traceId,
        long durationMs,
        String details) {
}
