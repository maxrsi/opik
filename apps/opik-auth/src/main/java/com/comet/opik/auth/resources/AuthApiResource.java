package com.comet.opik.auth.resources;

import com.comet.opik.auth.config.AuthSettings;
import com.comet.opik.auth.db.Records.ApiKeyWithOwner;
import com.comet.opik.auth.domain.AccountService;
import com.comet.opik.auth.domain.ApiError;
import com.comet.opik.auth.domain.AuthCore;
import com.comet.opik.auth.web.RequestMetas;
import com.comet.opik.auth.web.SessionPrincipals;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.CacheControl;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;

import java.util.List;
import java.util.Map;

/** Public, cookie authenticated API used by the selfhosted frontend plugin: login, logout, me, own API keys. */
@Path("/auth/api")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthApiResource {

    private final AccountService accounts;
    private final AuthCore authCore;
    private final SessionPrincipals principals;
    private final AuthSettings settings;

    public AuthApiResource(AccountService accounts, AuthCore authCore, SessionPrincipals principals,
            AuthSettings settings) {
        this.accounts = accounts;
        this.authCore = authCore;
        this.principals = principals;
        this.settings = settings;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record LoginRequest(String username, String password) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ChangePasswordRequest(String currentPassword, String newPassword) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record CreateApiKeyRequest(String name, Integer expiresInDays) {
    }

    public record Me(String userId, String username, String displayName, String email, String userType,
            String role, List<String> permissions, String workspaceId, String workspaceName, String uiApiKey,
            boolean mustChangePassword) {
    }

    @POST
    @Path("login")
    public Response login(LoginRequest request, @Context HttpServletRequest http) {
        if (request == null) {
            throw ApiError.badRequest("username and password are required");
        }
        var result = accounts.login(request.username(), request.password(), RequestMetas.of(http));
        return Response.ok(Map.of("mustChangePassword", result.mustChangePassword()))
                .cookie(sessionCookie(result.sessionToken(), (int) result.maxAgeSeconds()))
                .cacheControl(noStore())
                .build();
    }

    @POST
    @Path("logout")
    public Response logout(@Context HttpHeaders headers, @Context HttpServletRequest http) {
        try {
            accounts.logout(principals.require(headers), RequestMetas.of(http));
        } catch (ApiError e) {
            // already logged out / expired: still clear the cookie
        }
        return Response.noContent().cookie(sessionCookie("", 0)).build();
    }

    @GET
    @Path("me")
    public Response me(@Context HttpHeaders headers) {
        var p = principals.require(headers);
        var me = new Me(p.user().id(), p.username(), p.user().displayName(), p.user().email(), p.user().userType(),
                p.roleId(), p.permissions().stream().sorted().toList(), p.workspace().id(), p.workspace().name(),
                accounts.uiApiKey(p).orElse(null), p.user().mustChangePassword());
        return Response.ok(me).cacheControl(noStore()).build();
    }

    @POST
    @Path("me/password")
    public Response changePassword(ChangePasswordRequest request, @Context HttpHeaders headers,
            @Context HttpServletRequest http) {
        if (request == null) {
            throw ApiError.badRequest("currentPassword and newPassword are required");
        }
        accounts.changePassword(principals.require(headers), request.currentPassword(), request.newPassword(),
                RequestMetas.of(http));
        return Response.noContent().build();
    }

    @GET
    @Path("me/api-keys")
    public List<ApiKeyWithOwner> myApiKeys(@Context HttpHeaders headers) {
        return accounts.listMyApiKeys(principals.require(headers));
    }

    @POST
    @Path("me/api-keys")
    public Response createApiKey(CreateApiKeyRequest request, @Context HttpHeaders headers,
            @Context HttpServletRequest http) {
        var p = principals.require(headers);
        var created = accounts.createApiKey(p, request == null ? null : request.name(),
                request == null ? null : request.expiresInDays());
        accounts.audit().log(accounts.principalEvent(p, RequestMetas.of(http)).action("apikey.create")
                .outcome("success").status(201).resourceType("api_keys").resourceId(created.id()).build());
        return Response.status(201).entity(created).cacheControl(noStore()).build();
    }

    @DELETE
    @Path("me/api-keys/{id}")
    public Response revokeApiKey(@PathParam("id") String id, @Context HttpHeaders headers,
            @Context HttpServletRequest http) {
        var p = principals.require(headers);
        accounts.revokeApiKey(p, id, false);
        accounts.audit().log(accounts.principalEvent(p, RequestMetas.of(http)).action("apikey.revoke")
                .outcome("success").status(204).resourceType("api_keys").resourceId(id).build());
        return Response.noContent().build();
    }

    private NewCookie sessionCookie(String value, int maxAge) {
        return new NewCookie.Builder(settings.getCookieName())
                .value(value)
                .path("/")
                .maxAge(maxAge)
                .httpOnly(true)
                .secure(settings.isCookieSecure())
                .sameSite(NewCookie.SameSite.LAX)
                .build();
    }

    static CacheControl noStore() {
        var cc = new CacheControl();
        cc.setNoStore(true);
        cc.setNoCache(true);
        return cc;
    }
}
