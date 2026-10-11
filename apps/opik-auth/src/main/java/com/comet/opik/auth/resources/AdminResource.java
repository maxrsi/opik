package com.comet.opik.auth.resources;

import com.comet.opik.auth.audit.AuditQueryService;
import com.comet.opik.auth.db.RbacDao;
import com.comet.opik.auth.db.Records.ApiKeyWithOwner;
import com.comet.opik.auth.db.Records.UserWithRole;
import com.comet.opik.auth.domain.AccountService;
import com.comet.opik.auth.domain.ApiError;
import com.comet.opik.auth.domain.AuthCore;
import com.comet.opik.auth.domain.Permissions;
import com.comet.opik.auth.web.RequestMetas;
import com.comet.opik.auth.web.SessionPrincipals;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Admin API: users, roles, everyone's API keys, audit log query. */
@Path("/auth/api")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AdminResource {

    private final AccountService accounts;
    private final AuthCore authCore;
    private final RbacDao rbacDao;
    private final SessionPrincipals principals;
    private final AuditQueryService auditQuery;

    public AdminResource(AccountService accounts, AuthCore authCore, RbacDao rbacDao, SessionPrincipals principals,
            AuditQueryService auditQuery) {
        this.accounts = accounts;
        this.authCore = authCore;
        this.rbacDao = rbacDao;
        this.principals = principals;
        this.auditQuery = auditQuery;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record CreateUserRequest(String username, String displayName, String email, String role,
            String userType, String password) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record UpdateUserRequest(String displayName, String email, String role, String status) {
    }

    public record RoleView(String id, String displayName, String description, boolean builtin,
            List<String> permissions) {
    }

    // ------------------------------------------------------------------ users

    @GET
    @Path("users")
    public List<UserWithRole> listUsers(@Context HttpHeaders headers) {
        principals.require(headers, Permissions.USER_MANAGE);
        return accounts.listUsers();
    }

    @POST
    @Path("users")
    public Response createUser(CreateUserRequest request, @Context HttpHeaders headers,
            @Context HttpServletRequest http) {
        var p = principals.require(headers, Permissions.USER_MANAGE);
        if (request == null) {
            throw ApiError.badRequest("Body required");
        }
        var created = accounts.createUser(request.username(), request.displayName(), request.email(),
                StringUtils.defaultIfBlank(request.role(), "viewer"), request.userType(), request.password(),
                p.username());
        accounts.audit().log(accounts.principalEvent(p, RequestMetas.of(http)).action("admin.user.create")
                .outcome("success").status(201).resourceType("users").resourceId(created.user().id())
                .details(AccountService.toJson(Map.of("username", created.user().username(),
                        "role", String.valueOf(created.user().roleId()))))
                .build());
        var body = new LinkedHashMap<String, Object>();
        body.put("user", created.user());
        if (created.initialPassword() != null) {
            body.put("initialPassword", created.initialPassword());
        }
        return Response.status(201).entity(body).cacheControl(AuthApiResource.noStore()).build();
    }

    @PATCH
    @Path("users/{id}")
    public UserWithRole updateUser(@PathParam("id") String id, UpdateUserRequest request,
            @Context HttpHeaders headers, @Context HttpServletRequest http) {
        var p = principals.require(headers, Permissions.USER_MANAGE);
        if (request == null) {
            throw ApiError.badRequest("Body required");
        }
        var updated = accounts.updateUser(id, request.displayName(), request.email(), request.role(),
                request.status(), p.username());
        var details = new LinkedHashMap<String, String>();
        if (request.role() != null) {
            details.put("role", request.role());
        }
        if (request.status() != null) {
            details.put("status", request.status());
        }
        accounts.audit().log(accounts.principalEvent(p, RequestMetas.of(http))
                .action(request.role() != null ? "admin.role.assign" : "admin.user.update")
                .outcome("success").status(200).resourceType("users").resourceId(id)
                .details(AccountService.toJson(details)).build());
        return updated;
    }

    @POST
    @Path("users/{id}/reset-password")
    public Response resetPassword(@PathParam("id") String id, @Context HttpHeaders headers,
            @Context HttpServletRequest http) {
        var p = principals.require(headers, Permissions.USER_MANAGE);
        String password = accounts.resetPassword(id, p.username());
        accounts.audit().log(accounts.principalEvent(p, RequestMetas.of(http)).action("admin.user.reset_password")
                .outcome("success").status(200).resourceType("users").resourceId(id).build());
        return Response.ok(Map.of("password", password)).cacheControl(AuthApiResource.noStore()).build();
    }

    // ------------------------------------------------------------------ roles

    @GET
    @Path("roles")
    public List<RoleView> roles(@Context HttpHeaders headers) {
        principals.require(headers);
        return rbacDao.listRoles().stream()
                .map(r -> new RoleView(r.id(), r.displayName(), r.description(), r.builtin(),
                        authCore.permissionsOfRole(r.id()).stream().sorted().toList()))
                .toList();
    }

    // ------------------------------------------------------------------ all API keys

    @GET
    @Path("api-keys")
    public List<ApiKeyWithOwner> allApiKeys(@Context HttpHeaders headers) {
        principals.require(headers, Permissions.USER_MANAGE);
        return accounts.listAllApiKeys();
    }

    @DELETE
    @Path("api-keys/{id}")
    public Response revokeAnyApiKey(@PathParam("id") String id, @Context HttpHeaders headers,
            @Context HttpServletRequest http) {
        var p = principals.require(headers, Permissions.USER_MANAGE);
        accounts.revokeApiKey(p, id, true);
        accounts.audit().log(accounts.principalEvent(p, RequestMetas.of(http)).action("apikey.revoke")
                .outcome("success").status(204).resourceType("api_keys").resourceId(id).build());
        return Response.noContent().build();
    }

    // ------------------------------------------------------------------ audit

    @GET
    @Path("audit-logs")
    @Produces({MediaType.APPLICATION_JSON, "text/csv"})
    public Response auditLogs(@Context HttpHeaders headers,
            @QueryParam("from") String from, @QueryParam("to") String to,
            @QueryParam("actor") String actor, @QueryParam("action") String action,
            @QueryParam("resourceType") String resourceType, @QueryParam("resourceId") String resourceId,
            @QueryParam("outcome") String outcome, @QueryParam("source") String source,
            @QueryParam("status") Integer status,
            @QueryParam("page") Integer page, @QueryParam("size") Integer size,
            @QueryParam("format") String format) {
        var p = principals.require(headers, Permissions.AUDIT_LOG_VIEW);
        Instant toTs = parse(to, Instant.now());
        Instant fromTs = parse(from, toTs.minus(Duration.ofDays(7)));
        if (fromTs.isAfter(toTs)) {
            throw ApiError.badRequest("from must be before to");
        }
        if (Duration.between(fromTs, toTs).compareTo(AuditQueryService.MAX_RANGE) > 0) {
            throw ApiError.badRequest("Time range must not exceed 180 days");
        }
        var criteria = AuditQueryService.Criteria.builder()
                .workspaceId(p.workspace().id()).from(fromTs).to(toTs).actor(actor).action(action)
                .resourceType(resourceType).resourceId(resourceId).outcome(outcome).source(source).status(status)
                .build();
        if ("csv".equalsIgnoreCase(format)) {
            return Response.ok(auditQuery.exportCsv(criteria), "text/csv")
                    .header("Content-Disposition", "attachment; filename=\"audit-logs.csv\"")
                    .build();
        }
        int pageNo = page == null || page < 1 ? 1 : page;
        int pageSize = size == null || size < 1 ? 50 : Math.min(size, AuditQueryService.MAX_PAGE_SIZE);
        return Response.ok(auditQuery.find(criteria, pageNo, pageSize), MediaType.APPLICATION_JSON_TYPE).build();
    }

    private static Instant parse(String value, Instant fallback) {
        if (StringUtils.isBlank(value)) {
            return fallback;
        }
        try {
            return Instant.parse(value.strip());
        } catch (DateTimeParseException e) {
            throw ApiError.badRequest("Invalid ISO-8601 timestamp: " + value);
        }
    }
}
