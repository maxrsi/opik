package com.comet.opik.auth.bootstrap;

import com.comet.opik.auth.audit.AuditEvent;
import com.comet.opik.auth.audit.AuditLogger;
import com.comet.opik.auth.config.AuthSettings;
import com.comet.opik.auth.db.RbacDao;
import com.comet.opik.auth.db.UserDao;
import com.comet.opik.auth.domain.LocalPasswordProvider;
import com.comet.opik.auth.domain.PasswordHasher;
import com.comet.opik.auth.domain.Tokens;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jdbi.v3.core.Jdbi;

import java.time.Clock;

/**
 * Idempotent first-admin bootstrap: when the users table is empty, creates the admin user (local identity + Admin
 * membership of the default workspace). The password comes from {@code OPIK_AUTH_BOOTSTRAP_ADMIN_PASSWORD} or is
 * generated and printed once to the log. Either way the admin must change it at first login.
 */
@Slf4j
public final class BootstrapAdmin {

    private BootstrapAdmin() {
    }

    /** @return the generated password, or null if nothing was created or the password was configured. */
    public static String ensure(Jdbi jdbi, PasswordHasher hasher, AuthSettings settings, AuditLogger audit,
            Clock clock) {
        return jdbi.inTransaction(handle -> {
            var users = handle.attach(UserDao.class);
            // serialise concurrent replicas on the default workspace row
            handle.createQuery("SELECT id FROM workspaces WHERE is_default = TRUE FOR UPDATE").mapTo(String.class)
                    .findFirst();
            if (users.countUsers() > 0) {
                return null;
            }
            var rbac = handle.attach(RbacDao.class);
            var workspace = rbac.findWorkspaceByName(settings.getDefaultWorkspaceName())
                    .orElseThrow(() -> new IllegalStateException("default workspace missing"));
            String username = StringUtils.defaultIfBlank(settings.getBootstrapAdminUsername(), "admin").strip();
            boolean generated = StringUtils.isBlank(settings.getBootstrapAdminPassword());
            String password = generated ? Tokens.randomPassword(20) : settings.getBootstrapAdminPassword();
            String id = Tokens.uuidV7();
            users.insert(id, username, "Administrator", null, "human", true, "bootstrap");
            users.insertIdentity(Tokens.uuidV7(), id, LocalPasswordProvider.PROVIDER,
                    LocalPasswordProvider.subject(username), hasher.hash(password), clock.instant());
            rbac.upsertMember(workspace.id(), id, "admin", "bootstrap");
            if (generated) {
                log.warn("=== Initial admin password for '{}': {} === (shown once; change it at first login)",
                        username, password);
            } else {
                log.warn("=== Initial admin '{}' created with the configured bootstrap password ===", username);
            }
            audit.log(AuditEvent.builder().action("admin.bootstrap").outcome("success").status(201)
                    .actor("system").actorType("system").workspaceId(workspace.id())
                    .workspaceName(workspace.name()).resourceType("users").resourceId(id)
                    .details("{\"username\":\"" + username + "\"}").build());
            return generated ? password : null;
        });
    }
}
