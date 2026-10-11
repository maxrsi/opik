package com.comet.opik.auth.web;

import com.comet.opik.auth.config.AuthSettings;
import com.comet.opik.auth.domain.ApiError;
import com.comet.opik.auth.domain.AuthCore;
import com.comet.opik.auth.domain.Principal;
import jakarta.ws.rs.core.HttpHeaders;

/** Resolves the browser session (cookie) of a public /auth/api call against the default workspace. */
public class SessionPrincipals {

    private final AuthCore authCore;
    private final AuthSettings settings;

    public SessionPrincipals(AuthCore authCore, AuthSettings settings) {
        this.authCore = authCore;
        this.settings = settings;
    }

    public Principal require(HttpHeaders headers) {
        var cookie = headers.getCookies().get(settings.getCookieName());
        var credential = authCore.resolveSession(cookie == null ? null : cookie.getValue())
                .orElseThrow(ApiError::unauthorized);
        if (authCore.activeUser(credential).isEmpty()) {
            throw ApiError.unauthorized();
        }
        return authCore.principal(credential, authCore.defaultWorkspace())
                .orElseThrow(() -> ApiError.forbidden("User has no access to the workspace"));
    }

    public Principal require(HttpHeaders headers, String permission) {
        var principal = require(headers);
        if (!principal.has(permission)) {
            throw ApiError.forbidden("Missing permission: " + permission);
        }
        return principal;
    }
}
