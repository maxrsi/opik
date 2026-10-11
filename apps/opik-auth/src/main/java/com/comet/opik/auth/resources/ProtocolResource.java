package com.comet.opik.auth.resources;

import com.comet.opik.auth.audit.AuditEvent;
import com.comet.opik.auth.audit.AuditLogger;
import com.comet.opik.auth.config.AuthSettings;
import com.comet.opik.auth.db.Records.Workspace;
import com.comet.opik.auth.domain.ApiError;
import com.comet.opik.auth.domain.AuthCore;
import com.comet.opik.auth.domain.Credential;
import com.comet.opik.auth.domain.Principal;
import com.comet.opik.auth.web.RequestMetas;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.List;
import java.util.Optional;

/**
 * The "react-service" protocol consumed by opik-backend's {@code RemoteAuthService} and
 * {@code RemoteWorkspacePermissionsService}. Internal only: nginx does not route /opik/* or /workspaces/*.
 * <p>
 * Wire format is camelCase JSON; errors use the {@code {"msg","code"}} envelope ({@link ApiError}). Semantics:
 * <ul>
 * <li>401 – no / invalid / expired credential</li>
 * <li>403 – unknown workspace, not a member, or missing a required permission (never 404: a bare 404 is a 500 in
 * the backend)</li>
 * <li>400 – missing workspace name</li>
 * </ul>
 */
@Slf4j
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class ProtocolResource {

    private final AuthCore authCore;
    private final AuditLogger audit;
    private final AuthSettings settings;

    public ProtocolResource(AuthCore authCore, AuditLogger audit, AuthSettings settings) {
        this.authCore = authCore;
        this.audit = audit;
        this.settings = settings;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record AuthRequest(String workspaceName, String path, List<String> requiredPermissions) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record WorkspacePermissionsRequest(String workspaceName) {
    }

    public record AuthResponse(String user, String workspaceId, String workspaceName, List<Object> quotas) {
    }

    public record Permission(String permissionName, String permissionValue) {
    }

    public record WorkspaceUserPermissions(String userName, String workspaceName, List<Permission> permissions) {
    }

    /** RemoteAuthService reads {@code workspaceId}, {@code workspaceName} and {@code default}. */
    public record WorkspaceEntry(String workspaceId, String workspaceName,
            @com.fasterxml.jackson.annotation.JsonProperty("default") boolean isDefault) {
    }

    // ------------------------------------------------------------------ authentication

    @POST
    @Path("opik/auth")
    public AuthResponse authByApiKey(@Context HttpHeaders headers, @Context HttpServletRequest http,
            AuthRequest request) {
        return authorize(authCore.resolveAuthorization(headers.getHeaderString(HttpHeaders.AUTHORIZATION)),
                request, http);
    }

    @POST
    @Path("opik/auth-session")
    public AuthResponse authBySession(@Context HttpHeaders headers, @Context HttpServletRequest http,
            AuthRequest request) {
        return authorize(authCore.resolveSession(sessionCookie(headers)), request, http);
    }

    @POST
    @Path("opik/auth-by-username")
    public AuthResponse authByUsername() {
        // MCP OAuth is not supported in phase 1. JSON envelope 404 → backend answers 403 (bare 404 would be 500).
        throw ApiError.notFound("OAuth username authentication is not supported");
    }

    private AuthResponse authorize(Optional<Credential> credential, AuthRequest request, HttpServletRequest http) {
        if (request == null || StringUtils.isBlank(request.workspaceName())) {
            throw ApiError.badRequest("Workspace name should be provided");
        }
        var cred = credential.orElseThrow(ApiError::unauthorized);
        var workspace = authCore.findWorkspace(request.workspaceName())
                .orElseThrow(() -> ApiError.forbidden("User has no access to the workspace"));
        if (authCore.activeUser(cred).isEmpty()) {
            throw ApiError.unauthorized();
        }
        Principal principal = authCore.principal(cred, workspace)
                .orElseThrow(() -> ApiError.forbidden("User has no access to the workspace"));
        var missing = AuthCore.missing(principal.permissions(), request.requiredPermissions());
        if (!missing.isEmpty()) {
            audit.log(AuditEvent.builder()
                    .action("auth.permission_denied").outcome("denied").status(403)
                    .actor(principal.username()).actorType(principal.credentialType())
                    .credentialId(principal.credentialId())
                    .workspaceId(workspace.id()).workspaceName(workspace.name())
                    .path(StringUtils.defaultString(request.path())).route(StringUtils.defaultString(request.path()))
                    .resourceType("auth").requiredPermissions(request.requiredPermissions())
                    .clientIp(RequestMetas.clientIp(http))
                    .details("{\"missing\":\"" + String.join(",", missing) + "\"}")
                    .build());
            throw ApiError.forbidden("User has no permission: " + String.join(", ", missing));
        }
        return new AuthResponse(principal.username(), workspace.id(), workspace.name(), List.of());
    }

    // ------------------------------------------------------------------ permissions

    @POST
    @Path("opik/workspace-permissions")
    public WorkspaceUserPermissions permissionsByApiKey(@Context HttpHeaders headers,
            WorkspacePermissionsRequest request) {
        return permissions(authCore.resolveAuthorization(headers.getHeaderString(HttpHeaders.AUTHORIZATION)),
                request);
    }

    @POST
    @Path("opik/workspace-permissions-session")
    public WorkspaceUserPermissions permissionsBySession(@Context HttpHeaders headers,
            WorkspacePermissionsRequest request) {
        return permissions(authCore.resolveSession(sessionCookie(headers)), request);
    }

    @POST
    @Path("opik/workspace-permissions-by-username")
    public WorkspaceUserPermissions permissionsByUsername() {
        throw ApiError.notFound("OAuth username authentication is not supported");
    }

    private WorkspaceUserPermissions permissions(Optional<Credential> credential,
            WorkspacePermissionsRequest request) {
        if (request == null || StringUtils.isBlank(request.workspaceName())) {
            throw ApiError.badRequest("Workspace name should be provided");
        }
        var cred = credential.orElseThrow(ApiError::unauthorized);
        var workspace = authCore.findWorkspace(request.workspaceName())
                .orElseThrow(() -> ApiError.forbidden("User has no access to the workspace"));
        var principal = authCore.principal(cred, workspace)
                .orElseThrow(() -> ApiError.forbidden("User has no access to the workspace"));
        var permissions = principal.permissions().stream().sorted()
                .map(name -> new Permission(name, "true"))
                .toList();
        return new WorkspaceUserPermissions(principal.username(), workspace.name(), permissions);
    }

    // ------------------------------------------------------------------ workspaces

    @GET
    @Path("workspaces")
    public List<WorkspaceEntry> workspaces(@Context HttpHeaders headers,
            @QueryParam("withoutExtendedData") boolean withoutExtendedData) {
        var cred = authCore.resolveSession(sessionCookie(headers))
                .or(() -> authCore.resolveAuthorization(headers.getHeaderString(HttpHeaders.AUTHORIZATION)))
                .orElseThrow(ApiError::unauthorized);
        var workspace = authCore.defaultWorkspace();
        if (authCore.principal(cred, workspace).isEmpty()) {
            return List.of();
        }
        return List.of(new WorkspaceEntry(workspace.id(), workspace.name(), workspace.isDefault()));
    }

    @GET
    @Path("workspaces/workspace-id")
    @Produces(MediaType.TEXT_PLAIN)
    public String workspaceId(@QueryParam("name") String name) {
        return authCore.findWorkspace(name).map(Workspace::id)
                .orElseThrow(() -> ApiError.badRequest("Workspace not found"));
    }

    @GET
    @Path("workspaces/workspace-name")
    @Produces(MediaType.TEXT_PLAIN)
    public String workspaceName(@QueryParam("id") String id) {
        if (StringUtils.isBlank(id)) {
            throw ApiError.badRequest("Workspace id should be provided");
        }
        return authCore.findWorkspaceById(id).map(Workspace::name)
                .orElseThrow(() -> ApiError.notFound("Workspace not found"));
    }

    private String sessionCookie(HttpHeaders headers) {
        var cookie = headers.getCookies().get(settings.getCookieName());
        return cookie == null ? null : cookie.getValue();
    }
}
