package com.comet.opik.auth.db;

import java.time.Instant;

/** Row records mapped by JDBI's ConstructorMapper (snake_case columns → camelCase components). */
public final class Records {

    private Records() {
    }

    public record User(String id, String username, String displayName, String email, String status,
            String userType, boolean mustChangePassword, Instant createdAt, String createdBy, Instant lastLoginAt) {
        public boolean active() {
            return "active".equals(status);
        }
    }

    public record UserWithRole(String id, String username, String displayName, String email, String status,
            String userType, boolean mustChangePassword, Instant createdAt, String createdBy, Instant lastLoginAt,
            String roleId) {
    }

    public record Identity(String id, String userId, String provider, String subject, String secretHash) {
    }

    public record Session(String idHash, String userId, Instant createdAt, Instant lastSeenAt, Instant idleExpiresAt,
            Instant absExpiresAt, Instant revokedAt, String uiApiKeyId, byte[] uiApiKeyEnc) {
    }

    public record ApiKey(String id, String userId, String workspaceId, String name, String keyPrefix, String keyHash,
            String kind, String roleId, Instant createdAt, Instant expiresAt, Instant lastUsedAt, Instant revokedAt,
            String revokedBy) {
    }

    public record ApiKeyWithOwner(String id, String userId, String username, String name, String keyPrefix,
            String kind, String roleId, Instant createdAt, Instant expiresAt, Instant lastUsedAt, Instant revokedAt,
            String revokedBy) {
    }

    public record Role(String id, String displayName, String description, boolean builtin, int sortOrder) {
    }

    public record Workspace(String id, String name, boolean isDefault) {
    }

    public record LoginAttempt(String subject, String clientIp, int failedCount, Instant lockedUntil,
            Instant lastFailedAt) {
    }
}
