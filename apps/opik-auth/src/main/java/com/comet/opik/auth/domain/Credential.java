package com.comet.opik.auth.domain;

/**
 * A validated, not yet workspace-scoped credential.
 *
 * @param restrictRoleId optional role an API key is narrowed to (effective = user role ∩ this role)
 */
public record Credential(String userId, String type, String credentialId, String restrictRoleId,
        String sessionIdHash) {

    public static final String SESSION = "session";
    public static final String API_KEY = "api_key";
}
