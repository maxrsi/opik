package com.comet.opik.ext.audit;

import com.comet.opik.infrastructure.auth.RequestContext;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.inject.Provider;
import jakarta.inject.Singleton;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Captures the authenticated identity for the audit log. Runs after {@code AuthFilter} (priority USER) and stores
 * what it needs as a request property, because the response may be written on a reactor thread where the
 * {@code @RequestScoped} {@link RequestContext} is unavailable (same reasoning as {@code RedactionRequestFilter}).
 */
@jakarta.ws.rs.ext.Provider
@Singleton
@Priority(Priorities.USER + 200)
@RequiredArgsConstructor(onConstructor_ = @Inject)
public class AuditRequestFilter implements ContainerRequestFilter {

    public static final String AUDIT_CONTEXT_PROPERTY = "audit.ctx";

    record AuditContext(String userName, String workspaceId, String workspaceName) {
    }

    private final @NonNull Provider<RequestContext> requestContext;
    private final @NonNull AuditLogWriter writer;

    @Override
    public void filter(ContainerRequestContext context) {
        if (!writer.isEnabled() || !AuditResponseFilter.isAuditedPath(context.getUriInfo().getRequestUri().getPath())) {
            return;
        }
        try {
            var ctx = requestContext.get();
            context.setProperty(AUDIT_CONTEXT_PROPERTY,
                    new AuditContext(ctx.getUserName(), ctx.getWorkspaceId(), ctx.getWorkspaceName()));
        } catch (RuntimeException e) {
            // no request scope (e.g. unauthenticated path): the response filter records an anonymous actor
        }
    }
}
