package com.comet.opik.auth.domain;

import com.comet.opik.auth.audit.AuditEvent;
import com.comet.opik.auth.audit.AuditLogger;
import com.comet.opik.auth.config.AuthSettings;
import com.comet.opik.auth.db.ApiKeyDao;
import com.comet.opik.auth.db.LoginAttemptDao;
import com.comet.opik.auth.db.RbacDao;
import com.comet.opik.auth.db.Records.ApiKeyWithOwner;
import com.comet.opik.auth.db.Records.User;
import com.comet.opik.auth.db.Records.UserWithRole;
import com.comet.opik.auth.db.SessionDao;
import com.comet.opik.auth.db.UserDao;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jdbi.v3.core.Jdbi;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/** Login / logout, password management, user administration and API key lifecycle. */
@Slf4j
public class AccountService {

    public static final Set<String> USER_TYPES = Set.of("human", "service");
    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._@-]{1,99}$");
    private static final String INVALID_CREDENTIALS = "Invalid username or password";

    private final Jdbi jdbi;
    private final UserDao userDao;
    private final RbacDao rbacDao;
    private final SessionDao sessionDao;
    private final ApiKeyDao apiKeyDao;
    private final LoginAttemptDao loginAttemptDao;
    private final LocalPasswordProvider localProvider;
    private final PasswordHasher hasher;
    private final AuthCore authCore;
    private final AuditLogger audit;
    private final AuthSettings settings;
    private final Clock clock;

    public AccountService(Jdbi jdbi, PasswordHasher hasher, AuthCore authCore, AuditLogger audit,
            AuthSettings settings, Clock clock) {
        this.jdbi = jdbi;
        this.userDao = jdbi.onDemand(UserDao.class);
        this.rbacDao = jdbi.onDemand(RbacDao.class);
        this.sessionDao = jdbi.onDemand(SessionDao.class);
        this.apiKeyDao = jdbi.onDemand(ApiKeyDao.class);
        this.loginAttemptDao = jdbi.onDemand(LoginAttemptDao.class);
        this.hasher = hasher;
        this.localProvider = new LocalPasswordProvider(userDao, hasher, clock);
        this.authCore = authCore;
        this.audit = audit;
        this.settings = settings;
        this.clock = clock;
    }

    @Builder
    public record RequestMeta(String clientIp, String userAgent, String path, String method) {
    }

    public record LoginResult(String sessionToken, boolean mustChangePassword, long maxAgeSeconds, User user) {
    }

    public record CreatedApiKey(String id, String name, String key, String keyPrefix, Instant createdAt,
            Instant expiresAt) {
    }

    public record CreatedUser(UserWithRole user, String initialPassword) {
    }

    // ------------------------------------------------------------------ login / logout

    public LoginResult login(String username, String password, RequestMeta meta) {
        Instant now = clock.instant();
        String subject = StringUtils.isBlank(username) ? "" : LocalPasswordProvider.subject(username);
        String ip = StringUtils.defaultString(meta.clientIp());
        var attempt = loginAttemptDao.find(subject, ip).orElse(null);
        if (attempt != null && attempt.lockedUntil() != null && attempt.lockedUntil().isAfter(now)) {
            auditLogin(subject, null, "failure", 429, meta, Map.of("reason", "locked"));
            throw new ApiError(429, "Too many failed login attempts, try again later");
        }

        var userId = localProvider.authenticate(username, password);
        User user = userId.flatMap(userDao::findById).orElse(null);
        if (user == null || !user.active()) {
            int failures = (attempt == null ? 0 : attempt.failedCount()) + 1;
            Instant lockedUntil = failures >= settings.getLoginMaxFailures()
                    ? now.plus(settings.getLoginLockout().toJavaDuration())
                    : null;
            loginAttemptDao.upsert(subject, ip, lockedUntil != null ? 0 : failures, lockedUntil, now);
            auditLogin(subject, null, "failure", 401, meta,
                    Map.of("reason", user == null ? "invalid_credentials" : "user_disabled",
                            "locked", String.valueOf(lockedUntil != null)));
            throw ApiError.unauthorized(INVALID_CREDENTIALS);
        }
        if (attempt != null) {
            loginAttemptDao.clear(subject, ip);
        }

        var workspace = authCore.defaultWorkspace();
        Instant absExpiry = now.plus(settings.getSessionAbsoluteTimeout().toJavaDuration());
        Instant idleExpiry = min(now.plus(settings.getSessionIdleTimeout().toJavaDuration()), absExpiry);
        String token = Tokens.newSessionToken();
        String idHash = Tokens.sha256Hex(token);

        // Session-derived UI API key (Optimization Studio passes it to python-backend, which calls back with it).
        var material = Tokens.newApiKey();
        String uiKeyId = Tokens.uuidV7();
        jdbi.useTransaction(handle -> {
            handle.attach(ApiKeyDao.class).insert(uiKeyId, user.id(), workspace.id(), "ui-session",
                    material.prefix(), Tokens.sha256Hex(material.key()), "session", null, absExpiry);
            handle.attach(SessionDao.class).insert(idHash, user.id(), now, idleExpiry, absExpiry,
                    StringUtils.left(ip, 64), StringUtils.left(meta.userAgent(), 512), uiKeyId,
                    Tokens.encrypt(settings.getSecret(), material.key()));
            handle.attach(UserDao.class).touchLogin(user.id(), now);
        });
        audit.log(base(meta).action("auth.login.success").outcome("success").status(200)
                .actor(user.username()).actorType("session").credentialId(idHash.substring(0, 12))
                .workspaceId(workspace.id()).workspaceName(workspace.name()).resourceId(user.id()).build());
        long maxAge = Duration.between(now, absExpiry).toSeconds();
        return new LoginResult(token, user.mustChangePassword(), maxAge, user);
    }

    public void logout(Principal principal, RequestMeta meta) {
        revokeSession(principal.sessionIdHash(), principal.username());
        audit.log(principalEvent(principal, meta).action("auth.logout").outcome("success").status(204).build());
    }

    private void revokeSession(String idHash, String by) {
        if (idHash == null) {
            return;
        }
        Instant now = clock.instant();
        sessionDao.find(idHash).ifPresent(session -> {
            sessionDao.revoke(idHash, now);
            if (session.uiApiKeyId() != null) {
                apiKeyDao.revoke(session.uiApiKeyId(), now, by);
            }
        });
        authCore.invalidateAll();
    }

    private void revokeAllSessions(String userId, String exceptIdHash, String by) {
        for (var session : sessionDao.findActiveByUser(userId)) {
            if (!session.idHash().equals(exceptIdHash)) {
                revokeSession(session.idHash(), by);
            }
        }
    }

    public Optional<String> uiApiKey(Principal principal) {
        if (principal.sessionIdHash() == null) {
            return Optional.empty();
        }
        return sessionDao.find(principal.sessionIdHash())
                .filter(s -> s.uiApiKeyEnc() != null)
                .map(s -> {
                    try {
                        return Tokens.decrypt(settings.getSecret(), s.uiApiKeyEnc());
                    } catch (RuntimeException e) {
                        log.warn("Could not decrypt UI api key (secret rotated?)");
                        return null;
                    }
                });
    }

    // ------------------------------------------------------------------ passwords

    public void changePassword(Principal principal, String currentPassword, String newPassword, RequestMeta meta) {
        var identity = userDao.findIdentityByUser(principal.user().id(), LocalPasswordProvider.PROVIDER)
                .orElseThrow(() -> ApiError.badRequest("User has no local password"));
        if (!hasher.verify(StringUtils.defaultString(currentPassword), identity.secretHash())) {
            audit.log(principalEvent(principal, meta).action("auth.password.change").outcome("failure").status(400)
                    .details("{\"reason\":\"wrong_current_password\"}").build());
            throw ApiError.badRequest("Current password is incorrect");
        }
        validatePassword(principal.username(), newPassword);
        if (hasher.verify(newPassword, identity.secretHash())) {
            throw ApiError.badRequest("New password must differ from the current one");
        }
        userDao.updateLocalSecret(principal.user().id(), hasher.hash(newPassword), clock.instant());
        userDao.setMustChangePassword(principal.user().id(), false);
        revokeAllSessions(principal.user().id(), principal.sessionIdHash(), principal.username());
        audit.log(principalEvent(principal, meta).action("auth.password.change").outcome("success").status(204)
                .build());
    }

    public void validatePassword(String username, String password) {
        if (password == null || password.length() < settings.getPasswordMinLength()) {
            throw ApiError.badRequest("Password must be at least %d characters".formatted(
                    settings.getPasswordMinLength()));
        }
        if (password.length() > 256) {
            throw ApiError.badRequest("Password is too long");
        }
        if (username != null && password.equalsIgnoreCase(username)) {
            throw ApiError.badRequest("Password must not equal the username");
        }
    }

    // ------------------------------------------------------------------ user administration

    public List<UserWithRole> listUsers() {
        return userDao.listWithRole(authCore.defaultWorkspace().id());
    }

    /**
     * Creates a user (and its local identity + workspace membership). When {@code password} is blank a random one is
     * generated and returned once; the user must change it at first login either way.
     */
    public CreatedUser createUser(String username, String displayName, String email, String roleId,
            String userType, String password, String createdBy) {
        if (username == null || !USERNAME.matcher(username.strip()).matches()) {
            throw ApiError.badRequest("Username must be 2-100 chars of letters, digits, '.', '_', '@', '-'");
        }
        String normalized = username.strip();
        String type = StringUtils.defaultIfBlank(userType, "human");
        if (!USER_TYPES.contains(type)) {
            throw ApiError.badRequest("userType must be one of " + USER_TYPES);
        }
        requireRole(roleId);
        if (userDao.findByUsername(normalized).isPresent()
                || userDao.findIdentity(LocalPasswordProvider.PROVIDER,
                        LocalPasswordProvider.subject(normalized)).isPresent()) {
            throw ApiError.conflict("User already exists");
        }
        boolean generated = StringUtils.isBlank(password);
        String initial = generated ? Tokens.randomPassword(20) : password;
        validatePassword(normalized, initial);
        String id = Tokens.uuidV7();
        var workspace = authCore.defaultWorkspace();
        String hash = hasher.hash(initial);
        try {
            jdbi.useTransaction(handle -> {
                var users = handle.attach(UserDao.class);
                users.insert(id, normalized, StringUtils.trimToNull(displayName), StringUtils.trimToNull(email),
                        type, "human".equals(type), createdBy);
                users.insertIdentity(Tokens.uuidV7(), id, LocalPasswordProvider.PROVIDER,
                        LocalPasswordProvider.subject(normalized), hash, clock.instant());
                handle.attach(RbacDao.class).upsertMember(workspace.id(), id, roleId, createdBy);
            });
        } catch (RuntimeException e) {
            if (StringUtils.containsIgnoreCase(String.valueOf(e.getMessage()), "Duplicate")) {
                throw ApiError.conflict("User or email already exists");
            }
            throw e;
        }
        var created = userDao.findWithRole(workspace.id(), id).orElseThrow();
        return new CreatedUser(created, generated ? initial : null);
    }

    /** Partial update: any null argument is left unchanged. Guards the "at least one active admin" invariant. */
    public UserWithRole updateUser(String id, String displayName, String email, String roleId, String status,
            String updatedBy) {
        var workspace = authCore.defaultWorkspace();
        var existing = userDao.findWithRole(workspace.id(), id).orElseThrow(() -> ApiError.notFound("User not found"));
        if (status != null && !Set.of("active", "disabled").contains(status)) {
            throw ApiError.badRequest("status must be active or disabled");
        }
        if (roleId != null) {
            requireRole(roleId);
        }
        boolean losesAdmin = "admin".equals(existing.roleId()) && "active".equals(existing.status())
                && ((roleId != null && !"admin".equals(roleId)) || "disabled".equals(status));
        if (losesAdmin && rbacDao.countActiveAdmins(workspace.id()) <= 1) {
            throw ApiError.conflict("Cannot demote or disable the last active Admin");
        }
        jdbi.useTransaction(handle -> {
            var users = handle.attach(UserDao.class);
            if (displayName != null || email != null) {
                users.updateProfile(id,
                        displayName != null ? StringUtils.trimToNull(displayName) : existing.displayName(),
                        email != null ? StringUtils.trimToNull(email) : existing.email());
            }
            if (status != null) {
                users.updateStatus(id, status);
            }
            if (roleId != null) {
                handle.attach(RbacDao.class).upsertMember(workspace.id(), id, roleId, updatedBy);
            }
        });
        if ("disabled".equals(status)) {
            revokeAllSessions(id, null, updatedBy);
        }
        authCore.invalidateAll();
        return userDao.findWithRole(workspace.id(), id).orElseThrow();
    }

    public String resetPassword(String userId, String by) {
        var user = userDao.findById(userId).orElseThrow(() -> ApiError.notFound("User not found"));
        String password = Tokens.randomPassword(20);
        Instant now = clock.instant();
        if (userDao.updateLocalSecret(userId, hasher.hash(password), now) == 0) {
            userDao.insertIdentity(Tokens.uuidV7(), userId, LocalPasswordProvider.PROVIDER,
                    LocalPasswordProvider.subject(user.username()), hasher.hash(password), now);
        }
        userDao.setMustChangePassword(userId, true);
        revokeAllSessions(userId, null, by);
        authCore.invalidateAll();
        return password;
    }

    private void requireRole(String roleId) {
        if (StringUtils.isBlank(roleId) || rbacDao.findRole(roleId).isEmpty()) {
            throw ApiError.badRequest("Unknown role '%s'".formatted(roleId));
        }
    }

    // ------------------------------------------------------------------ API keys

    public CreatedApiKey createApiKey(Principal principal, String name, Integer expiresInDays) {
        if (StringUtils.isBlank(name) || name.strip().length() > 100) {
            throw ApiError.badRequest("name is required (max 100 chars)");
        }
        if (expiresInDays != null && (expiresInDays < 1 || expiresInDays > 3650)) {
            throw ApiError.badRequest("expiresInDays must be between 1 and 3650");
        }
        var material = Tokens.newApiKey();
        String id = Tokens.uuidV7();
        Instant now = clock.instant();
        Instant expiresAt = expiresInDays == null ? null : now.plus(Duration.ofDays(expiresInDays));
        apiKeyDao.insert(id, principal.user().id(), principal.workspace().id(), name.strip(), material.prefix(),
                Tokens.sha256Hex(material.key()), "personal", null, expiresAt);
        return new CreatedApiKey(id, name.strip(), material.key(), material.prefix(), now, expiresAt);
    }

    public List<ApiKeyWithOwner> listMyApiKeys(Principal principal) {
        return apiKeyDao.listPersonalOfUser(principal.user().id());
    }

    public List<ApiKeyWithOwner> listAllApiKeys() {
        return apiKeyDao.listAllPersonal();
    }

    /** @param asAdmin when false the key must belong to the caller */
    public void revokeApiKey(Principal principal, String keyId, boolean asAdmin) {
        var key = apiKeyDao.findById(keyId).filter(k -> "personal".equals(k.kind()))
                .orElseThrow(() -> ApiError.notFound("API key not found"));
        if (!asAdmin && !key.userId().equals(principal.user().id())) {
            throw ApiError.notFound("API key not found");
        }
        apiKeyDao.revoke(keyId, clock.instant(), principal.username());
        authCore.invalidateAll();
    }

    // ------------------------------------------------------------------ audit helpers

    public AuditLogger audit() {
        return audit;
    }

    private void auditLogin(String subject, User user, String outcome, int status, RequestMeta meta,
            Map<String, String> details) {
        var ws = authCore.findWorkspace(settings.getDefaultWorkspaceName()).orElse(null);
        audit.log(base(meta).action("auth.login.failure").outcome(outcome).status(status)
                .actor(user != null ? user.username() : StringUtils.left(subject, 100))
                .workspaceId(ws != null ? ws.id() : "").workspaceName(ws != null ? ws.name() : "")
                .details(toJson(details)).build());
    }

    public AuditEvent.AuditEventBuilder principalEvent(Principal p, RequestMeta meta) {
        return base(meta).actor(p.username()).actorType(p.credentialType()).credentialId(p.credentialId())
                .workspaceId(p.workspace().id()).workspaceName(p.workspace().name());
    }

    public static AuditEvent.AuditEventBuilder base(RequestMeta meta) {
        return AuditEvent.builder().clientIp(meta.clientIp()).userAgent(meta.userAgent()).path(meta.path())
                .route(meta.path()).httpMethod(meta.method()).resourceType("auth");
    }

    public static String toJson(Map<String, String> map) {
        var sb = new StringBuilder("{");
        map.forEach((k, v) -> {
            if (sb.length() > 1) {
                sb.append(',');
            }
            sb.append('"').append(escape(k)).append("\":\"").append(escape(v)).append('"');
        });
        return sb.append('}').toString();
    }

    private static String escape(String s) {
        return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static Instant min(Instant a, Instant b) {
        return a.isBefore(b) ? a : b;
    }
}
