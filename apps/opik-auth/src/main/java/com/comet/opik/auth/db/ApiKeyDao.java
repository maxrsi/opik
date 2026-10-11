package com.comet.opik.auth.db;

import com.comet.opik.auth.db.Records.ApiKey;
import com.comet.opik.auth.db.Records.ApiKeyWithOwner;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@RegisterConstructorMapper(ApiKey.class)
@RegisterConstructorMapper(ApiKeyWithOwner.class)
public interface ApiKeyDao {

    String COLUMNS = "id, user_id, workspace_id, name, key_prefix, key_hash, kind, role_id, created_at, expires_at, "
            + "last_used_at, revoked_at, revoked_by";
    String OWNER_COLUMNS = "k.id, k.user_id, u.username, k.name, k.key_prefix, k.kind, k.role_id, k.created_at, "
            + "k.expires_at, k.last_used_at, k.revoked_at, k.revoked_by";

    @SqlUpdate("INSERT INTO api_keys (id, user_id, workspace_id, name, key_prefix, key_hash, kind, role_id, expires_at) "
            + "VALUES (:id, :userId, :workspaceId, :name, :keyPrefix, :keyHash, :kind, :roleId, :expiresAt)")
    void insert(@Bind("id") String id, @Bind("userId") String userId, @Bind("workspaceId") String workspaceId,
            @Bind("name") String name, @Bind("keyPrefix") String keyPrefix, @Bind("keyHash") String keyHash,
            @Bind("kind") String kind, @Bind("roleId") String roleId, @Bind("expiresAt") Instant expiresAt);

    @SqlQuery("SELECT " + COLUMNS + " FROM api_keys WHERE key_prefix = :prefix")
    Optional<ApiKey> findByPrefix(@Bind("prefix") String prefix);

    @SqlQuery("SELECT " + COLUMNS + " FROM api_keys WHERE id = :id")
    Optional<ApiKey> findById(@Bind("id") String id);

    @SqlQuery("SELECT " + OWNER_COLUMNS + " FROM api_keys k JOIN users u ON u.id = k.user_id "
            + "WHERE k.user_id = :userId AND k.kind = 'personal' ORDER BY k.created_at DESC")
    List<ApiKeyWithOwner> listPersonalOfUser(@Bind("userId") String userId);

    @SqlQuery("SELECT " + OWNER_COLUMNS + " FROM api_keys k JOIN users u ON u.id = k.user_id "
            + "WHERE k.kind = 'personal' ORDER BY k.created_at DESC")
    List<ApiKeyWithOwner> listAllPersonal();

    @SqlUpdate("UPDATE api_keys SET revoked_at = :now, revoked_by = :by WHERE id = :id AND revoked_at IS NULL")
    int revoke(@Bind("id") String id, @Bind("now") Instant now, @Bind("by") String by);

    @SqlUpdate("UPDATE api_keys SET revoked_at = :now, revoked_by = :by "
            + "WHERE user_id = :userId AND kind = 'session' AND revoked_at IS NULL")
    int revokeSessionKeysOfUser(@Bind("userId") String userId, @Bind("now") Instant now, @Bind("by") String by);

    @SqlUpdate("UPDATE api_keys SET last_used_at = :now WHERE id = :id")
    void touch(@Bind("id") String id, @Bind("now") Instant now);
}
