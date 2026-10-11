package com.comet.opik.ext.audit;

import com.comet.opik.infrastructure.OpikConfiguration;
import com.comet.opik.infrastructure.auth.AuthDynamicFeature;
import com.comet.opik.infrastructure.auth.RequestContext;
import com.fasterxml.uuid.Generators;
import io.opentelemetry.api.trace.Span;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.HttpMethod;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.HttpHeaders;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.uri.UriTemplate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Builds an {@link AuditEvent} for every audited request and hands it to {@link AuditLogWriter}:
 * <ul>
 * <li>POST/PUT/PATCH/DELETE under {@code /v1/private/} that are not excluded by {@code audit.excludeRoutes};</li>
 * <li>requests rejected with 403 (any method) or 401 (write methods), when {@code audit.recordDenied}.</li>
 * </ul>
 * Action is {@code <resource>.<method>} derived from the matched resource class/method (e.g.
 * {@code projects.deleteById}); denied requests use {@code http.denied}. Also a pre-matching request filter that
 * records the start time.
 */
@Slf4j
@jakarta.ws.rs.ext.Provider
@Singleton
@PreMatching
@Priority(Priorities.AUTHENTICATION - 100)
public class AuditResponseFilter implements ContainerRequestFilter, ContainerResponseFilter {

    static final String START_NANOS_PROPERTY = "audit.startNanos";
    private static final String PRIVATE_PREFIX = "/v1/private/";
    private static final Set<String> WRITE_METHODS = Set.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH,
            HttpMethod.DELETE);

    private final AuditLogWriter writer;
    private final AuditConfig config;
    private final List<Pattern> excluded;

    @Inject
    public AuditResponseFilter(@NonNull AuditLogWriter writer, @NonNull OpikConfiguration configuration) {
        this.writer = writer;
        this.config = configuration.getAudit();
        this.excluded = config.getExcludeRoutes().stream().filter(StringUtils::isNotBlank).map(Pattern::compile)
                .toList();
    }

    static boolean isAuditedPath(String path) {
        return path != null && path.startsWith(PRIVATE_PREFIX);
    }

    @Override
    public void filter(ContainerRequestContext request) {
        if (writer.isEnabled()) {
            request.setProperty(START_NANOS_PROPERTY, System.nanoTime());
        }
    }

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        if (!writer.isEnabled()) {
            return;
        }
        try {
            String path = request.getUriInfo().getRequestUri().getPath();
            if (!isAuditedPath(path)) {
                return;
            }
            String method = request.getMethod();
            int status = response.getStatus();
            boolean write = WRITE_METHODS.contains(method);
            boolean denied = status == 403 || (status == 401 && write);
            if (denied) {
                if (!config.isRecordDenied()) {
                    return;
                }
            } else if (!write || isExcluded(method + " " + path)) {
                return;
            }
            writer.offer(buildEvent(request, response, path, method, status, denied));
        } catch (RuntimeException e) {
            log.warn("Failed to build audit event", e);
        }
    }

    boolean isExcluded(String methodAndPath) {
        for (Pattern pattern : excluded) {
            if (pattern.matcher(methodAndPath).matches()) {
                return true;
            }
        }
        return false;
    }

    private AuditEvent buildEvent(ContainerRequestContext request, ContainerResponseContext response, String path,
            String method, int status, boolean denied) {
        String resourceType = "";
        String action = "";
        String route = path;
        Map<String, String> pathParams = new LinkedHashMap<>();
        if (request instanceof ContainerRequest containerRequest) {
            var uriInfo = containerRequest.getUriInfo();
            var resourceMethod = uriInfo.getMatchedResourceMethod();
            if (resourceMethod != null && resourceMethod.getInvocable() != null) {
                var invocable = resourceMethod.getInvocable();
                Class<?> handler = invocable.getHandler().getHandlerClass();
                resourceType = resourceType(handler.getSimpleName());
                action = resourceType + "." + invocable.getDefinitionMethod().getName();
            }
            List<UriTemplate> templates = new ArrayList<>(uriInfo.getMatchedTemplates());
            if (!templates.isEmpty()) {
                Collections.reverse(templates);
                var sb = new StringBuilder();
                templates.forEach(t -> sb.append('/').append(t.getTemplate()));
                route = sb.toString().replaceAll("/{2,}", "/");
                if (route.length() > 1 && route.endsWith("/")) {
                    route = route.substring(0, route.length() - 1);
                }
            }
            uriInfo.getPathParameters().forEach((k, v) -> pathParams.put(k, v.isEmpty() ? "" : v.getFirst()));
        }

        var ctx = request
                .getProperty(AuditRequestFilter.AUDIT_CONTEXT_PROPERTY) instanceof AuditRequestFilter.AuditContext c
                        ? c
                        : null;
        String actorType = request.getCookies().containsKey(RequestContext.SESSION_COOKIE)
                ? "session"
                : StringUtils.isNotBlank(request.getHeaderString(HttpHeaders.AUTHORIZATION)) ? "api_key" : "anonymous";
        Object start = request.getProperty(START_NANOS_PROPERTY);
        long durationMs = start instanceof Long nanos ? (System.nanoTime() - nanos) / 1_000_000 : 0;
        @SuppressWarnings("unchecked")
        List<String> required = request
                .getProperty(AuthDynamicFeature.REQUIRED_PERMISSIONS_PROPERTY) instanceof List<?> l
                        ? (List<String>) l
                        : List.of();
        var spanContext = Span.current().getSpanContext();

        String details = denied && StringUtils.isNotBlank(action) ? "{\"attempted\":\"" + action + "\"}" : "{}";
        return AuditEvent.builder()
                .id(Generators.timeBasedEpochGenerator().generate().toString())
                .eventTime(Instant.now())
                .workspaceId(ctx != null ? ctx.workspaceId() : "")
                .workspaceName(ctx != null && ctx.workspaceName() != null
                        ? ctx.workspaceName()
                        : StringUtils.defaultString(request.getHeaderString(RequestContext.WORKSPACE_HEADER)))
                .actor(ctx != null ? ctx.userName() : "")
                .actorType(ctx != null || denied ? actorType : "anonymous")
                .credentialId("")
                .action(denied ? "http.denied" : StringUtils.defaultIfBlank(action, "http.write"))
                .outcome(denied ? "denied" : status < 400 ? "success" : "failure")
                .httpMethod(method)
                .route(route)
                .path(path)
                .status(status)
                .resourceType(resourceType)
                .resourceId(resourceId(pathParams, response))
                .pathParams(pathParams)
                .requiredPermissions(required)
                .clientIp(clientIp(request))
                .userAgent(request.getHeaderString(HttpHeaders.USER_AGENT))
                .traceId(spanContext.isValid() ? spanContext.getTraceId() : "")
                .durationMs(durationMs)
                .details(details)
                .build();
    }

    /** {@code ProjectsResource} → {@code projects}, {@code FeedbackDefinitionResource} → {@code feedbackDefinition}. */
    static String resourceType(String simpleClassName) {
        String name = StringUtils.removeEnd(simpleClassName, "Resource");
        return name.isEmpty() ? simpleClassName : Character.toLowerCase(name.charAt(0)) + name.substring(1);
    }

    static String resourceId(Map<String, String> pathParams, ContainerResponseContext response) {
        for (var entry : pathParams.entrySet()) {
            String key = entry.getKey().toLowerCase();
            if (key.equals("id") || key.endsWith("id") || key.endsWith("_id")) {
                return entry.getValue();
            }
        }
        if (response.getLocation() != null) {
            String location = response.getLocation().getPath();
            return StringUtils.substringAfterLast(location, "/");
        }
        return "";
    }

    static String clientIp(ContainerRequestContext request) {
        String xff = request.getHeaderString("X-Forwarded-For");
        if (StringUtils.isNotBlank(xff)) {
            return StringUtils.left(xff.split(",")[0].strip(), 64);
        }
        return StringUtils.left(StringUtils.defaultString(request.getHeaderString("X-Real-IP")).strip(), 64);
    }
}
