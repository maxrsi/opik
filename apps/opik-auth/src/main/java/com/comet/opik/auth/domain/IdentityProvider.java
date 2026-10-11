package com.comet.opik.auth.domain;

import java.util.Optional;

/**
 * A way to prove who a user is. Phase 1 only ships {@link LocalPasswordProvider}; a future OIDC provider adds a
 * {@code user_identities(provider='oidc:<alias>', subject=<sub>)} row for the same user and reuses the session,
 * role binding and audit code unchanged.
 */
public interface IdentityProvider {

    String id();

    /** @return the user id when the credentials are valid. */
    Optional<String> authenticate(String username, String secret);
}
