package com.comet.opik.auth.web;

import com.comet.opik.auth.domain.ApiError;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.MediaType;
import org.apache.commons.lang3.StringUtils;

import java.net.URI;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * CSRF defence for the cookie-authenticated public API (/auth/api/*), on top of {@code SameSite=Lax}:
 * <ul>
 * <li>state changing requests with a body must be {@code application/json} (not producible by a cross-site HTML
 * form, and triggers a CORS preflight for fetch);</li>
 * <li>if the browser sends {@code Origin} (or only {@code Referer}), it must be one of the configured public
 * origins.</li>
 * </ul>
 */
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public class CsrfFilter implements ContainerRequestFilter {

    private static final Set<String> SAFE = Set.of("GET", "HEAD", "OPTIONS");
    private final Set<String> allowedOrigins;

    public CsrfFilter(String publicOrigins) {
        this.allowedOrigins = Arrays.stream(StringUtils.defaultString(publicOrigins).split(","))
                .map(String::strip).filter(StringUtils::isNotBlank)
                .map(o -> StringUtils.removeEnd(o, "/").toLowerCase())
                .collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        String path = "/" + StringUtils.removeStart(ctx.getUriInfo().getPath(), "/");
        if (!path.startsWith("/auth/api/") || SAFE.contains(ctx.getMethod())) {
            return;
        }
        if (ctx.hasEntity() && (ctx.getMediaType() == null
                || !ctx.getMediaType().isCompatible(MediaType.APPLICATION_JSON_TYPE))) {
            throw new ApiError(415, "Content-Type must be application/json");
        }
        if (allowedOrigins.isEmpty()) {
            return;
        }
        String origin = ctx.getHeaderString("Origin");
        if (StringUtils.isBlank(origin)) {
            String referer = ctx.getHeaderString("Referer");
            if (StringUtils.isNotBlank(referer)) {
                try {
                    var uri = URI.create(referer);
                    origin = uri.getScheme() + "://" + uri.getRawAuthority();
                } catch (IllegalArgumentException e) {
                    throw ApiError.forbidden("Invalid Referer");
                }
            }
        }
        // Non-browser clients (curl, scripts) send neither header; they cannot carry a victim's cookie anyway.
        if (StringUtils.isNotBlank(origin) && !allowedOrigins.contains(StringUtils.removeEnd(origin, "/")
                .toLowerCase())) {
            throw ApiError.forbidden("Cross-origin request rejected");
        }
    }
}
