package com.comet.opik.auth.domain;

import com.comet.opik.auth.config.AuthSettings;
import com.comet.opik.auth.db.ApiKeyDao;
import com.comet.opik.auth.db.RbacDao;
import com.comet.opik.auth.db.Records;
import com.comet.opik.auth.db.Records.User;
import com.comet.opik.auth.db.Records.Workspace;
import com.comet.opik.auth.db.SessionDao;
import com.comet.opik.auth.db.UserDao;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Credential resolution (session token / API key) and role → permission evaluation.
 * <p>
 * Hot path of every opik-backend request, so validated credentials and role permissions are cached in-process for
 * 10 seconds. Logout / revocation / role changes invalidate the caches eagerly; with several opik-auth replicas the
 * worst case staleness is the TTL.
 */
@Slf4j
public class AuthCore {

    private static final Duration CACHE_TTL = Duration.ofSeconds(10);
    private static final Duration TOUCH_INTERVAL = Duration.ofSeconds(60);

    private final UserDao userDao;
    private final RbacDao rbacDao;
    private final SessionDao sessionDao;
    private final ApiKeyDao apiKeyDao;
    private final AuthSettings settings;
    private final Clock clock;

    private final Cache<String, CachedCredential> credentialCache = Caffeine.newBuilder()
            .expireAfterWrite(CACHE_TTL).maximumSize(100_000).build();
    private final Cache<String, Set<String>> rolePermissionCache = Caffeine.newBuilder()
            .expireAfterWrite(CACHE_TTL).build();
    private final Cache<String, Optional<String>> memberRoleCache = Caffeine.newBuilder()
            .expireAfterWrite(CACHE_TTL).maximumSize(100_000).build();
    private final ConcurrentHashMap<String, Instant> lastTouched = new ConcurrentHashMap<>();

    public AuthCore(UserDao userDao, RbacDao rbacDao, SessionDao sessionDao, ApiKeyDao apiKeyDao,
            AuthSettings settings, Clock clock) {
        this.userDao = userDao;
        this.rbacDao = rbacDao;
        this.sessionDao = sessionDao;
        this.apiKeyDao = apiKeyDao;
        this.settings = settings;
        this.clock = clock;
    }

    private record CachedCredential(Credential credential, Instant expiresAt) {
    }

    // ------------------------------------------------------------------ credentials

    /** Resolves a browser session token ({@code ops_...}). */
    public Optional<Credential> resolveSession(String token) {
        if (StringUtils.isBlank(token) || !token.startsWith(Tokens.SESSION_PREFIX)) {
            return Optional.empty();
        }
        String hash = Tokens.sha256Hex(token);
        Instant now = clock.instant();
        var cached = credentialCache.getIfPresent(hash);
        if (cached != null && cached.expiresAt().isAfter(now)) {
            touchSession(hash, now);
            return Optional.of(cached.credential());
        }
        var session = sessionDao.find(hash).orElse(null);
        if (session == null || session.revokedAt() != null || !session.idleExpiresAt().isAfter(now)
                || !session.absExpiresAt().isAfter(now)) {
            credentialCache.invalidate(hash);
            return Optional.empty();
        }
        var credential = new Credential(session.userId(), Credential.SESSION, hash.substring(0, 12), null, hash);
        Instant expiry = session.idleExpiresAt().isBefore(session.absExpiresAt())
                ? session.idleExpiresAt()
                : session.absExpiresAt();
        credentialCache.put(hash, new CachedCredential(credential, expiry));
        touchSession(hash, now);
        return Optional.of(credential);
    }

    /**
     * Resolves the {@code Authorization} header value. Accepts API keys ({@code opk_...}) and also session tokens:
     * opik-backend stores the session token in {@code RequestContext.apiKey} for browser requests and forwards it as
     * {@code Authorization} to {@code POST /opik/workspace-permissions}.
     */
    public Optional<Credential> resolveAuthorization(String value) {
        if (StringUtils.isBlank(value)) {
            return Optional.empty();
        }
        String token = value.strip();
        if (token.regionMatches(true, 0, "Bearer ", 0, 7)) {
            token = token.substring(7).strip();
        }
        if (token.startsWith(Tokens.SESSION_PREFIX)) {
            return resolveSession(token);
        }
        return resolveApiKey(token);
    }

    public Optional<Credential> resolveApiKey(String key) {
        String prefix = Tokens.apiKeyPrefix(key);
        if (prefix == null) {
            return Optional.empty();
        }
        String hash = Tokens.sha256Hex(key);
        Instant now = clock.instant();
        var cached = credentialCache.getIfPresent(hash);
        if (cached != null && cached.expiresAt().isAfter(now)) {
            touchApiKey(cached.credential().credentialId(), now);
            return Optional.of(cached.credential());
        }
        var apiKey = apiKeyDao.findByPrefix(prefix).orElse(null);
        if (apiKey == null || !Tokens.constantTimeEquals(apiKey.keyHash(), hash) || apiKey.revokedAt() != null
                || (apiKey.expiresAt() != null && !apiKey.expiresAt().isAfter(now))) {
            credentialCache.invalidate(hash);
            return Optional.empty();
        }
        var credential = new Credential(apiKey.userId(), Credential.API_KEY, apiKey.id(), apiKey.roleId(), null);
        Instant expiry = apiKey.expiresAt() == null ? Instant.MAX : apiKey.expiresAt();
        credentialCache.put(hash, new CachedCredential(credential, expiry));
        touchApiKey(apiKey.id(), now);
        return Optional.of(credential);
    }

    // ------------------------------------------------------------------ authorization

    public Optional<Workspace> findWorkspace(String name) {
        return StringUtils.isBlank(name) ? Optional.empty() : rbacDao.findWorkspaceByName(name.strip());
    }

    public Optional<Workspace> findWorkspaceById(String id) {
        return rbacDao.findWorkspaceById(id);
    }

    public Workspace defaultWorkspace() {
        return rbacDao.findWorkspaceByName(settings.getDefaultWorkspaceName())
                .orElseThrow(() -> new IllegalStateException("default workspace missing"));
    }

    /**
     * Resolves the full principal. Returns empty when the user is missing / disabled or is not a member of the
     * workspace (callers decide between 401 and 403).
     */
    public Optional<Principal> principal(Credential credential, Workspace workspace) {
        User user = userDao.findById(credential.userId()).orElse(null);
        if (user == null || !user.active()) {
            return Optional.empty();
        }
        var roleId = memberRoleCache.get(workspace.id() + "|" + user.id(),
                k -> rbacDao.roleOf(workspace.id(), user.id())).orElse(null);
        if (roleId == null) {
            return Optional.empty();
        }
        Set<String> permissions = new HashSet<>(permissionsOfRole(roleId));
        if (credential.restrictRoleId() != null) {
            permissions.retainAll(permissionsOfRole(credential.restrictRoleId()));
        }
        return Optional.of(new Principal(user, workspace, roleId, Set.copyOf(permissions), credential.type(),
                credential.credentialId(), credential.sessionIdHash()));
    }

    public Optional<User> activeUser(Credential credential) {
        return userDao.findById(credential.userId()).filter(Records.User::active);
    }

    public Set<String> permissionsOfRole(String roleId) {
        return rolePermissionCache.get(roleId, id -> Set.copyOf(rbacDao.permissionsOfRole(id)));
    }

    public static List<String> missing(Set<String> granted, List<String> required) {
        return required == null ? List.of() : required.stream().filter(p -> !granted.contains(p)).toList();
    }

    // ------------------------------------------------------------------ cache invalidation

    public void invalidateSession(String idHash) {
        credentialCache.invalidate(idHash);
    }

    public void invalidateAll() {
        credentialCache.invalidateAll();
        memberRoleCache.invalidateAll();
        rolePermissionCache.invalidateAll();
    }

    // ------------------------------------------------------------------ throttled bookkeeping

    private void touchSession(String hash, Instant now) {
        if (shouldTouch("s:" + hash, now)) {
            try {
                sessionDao.touch(hash, now, now.plus(settings.getSessionIdleTimeout().toJavaDuration()));
                credentialCache.invalidate(hash); // pick up the new idle expiry on next lookup
            } catch (RuntimeException e) {
                log.warn("Failed to touch session", e);
            }
        }
    }

    private void touchApiKey(String id, Instant now) {
        if (shouldTouch("k:" + id, now)) {
            try {
                apiKeyDao.touch(id, now);
            } catch (RuntimeException e) {
                log.warn("Failed to touch api key", e);
            }
        }
    }

    private boolean shouldTouch(String key, Instant now) {
        var previous = lastTouched.get(key);
        if (previous != null && Duration.between(previous, now).compareTo(TOUCH_INTERVAL) < 0) {
            return false;
        }
        lastTouched.put(key, now);
        if (lastTouched.size() > 200_000) {
            lastTouched.clear();
        }
        return true;
    }
}
