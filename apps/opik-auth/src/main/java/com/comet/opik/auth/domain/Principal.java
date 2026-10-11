package com.comet.opik.auth.domain;

import com.comet.opik.auth.db.Records.User;
import com.comet.opik.auth.db.Records.Workspace;

import java.util.Set;

/**
 * An authenticated caller resolved against one workspace.
 *
 * @param credentialType {@code session} or {@code api_key}
 * @param credentialId   api_keys.id, or the first 12 chars of the session id hash. Never the secret itself.
 */
public record Principal(User user, Workspace workspace, String roleId, Set<String> permissions,
        String credentialType, String credentialId, String sessionIdHash) {

    public boolean has(String permission) {
        return permissions.contains(permission);
    }

    public String username() {
        return user.username();
    }
}
