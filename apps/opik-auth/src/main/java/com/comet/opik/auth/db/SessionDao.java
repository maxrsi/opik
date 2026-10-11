package com.comet.opik.auth.db;

import com.comet.opik.auth.db.Records.Session;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@RegisterConstructorMapper(Session.class)
public interface SessionDao {

    String COLUMNS = "id_hash, user_id, created_at, last_seen_at, idle_expires_at, abs_expires_at, revoked_at, "
            + "ui_api_key_id, ui_api_key_enc";

    @SqlUpdate("INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, idle_expires_at, abs_expires_at, "
            + "client_ip, user_agent, ui_api_key_id, ui_api_key_enc) VALUES (:idHash, :userId, :now, :now, "
            + ":idleExpiresAt, :absExpiresAt, :clientIp, :userAgent, :uiApiKeyId, :uiApiKeyEnc)")
    void insert(@Bind("idHash") String idHash, @Bind("userId") String userId, @Bind("now") Instant now,
            @Bind("idleExpiresAt") Instant idleExpiresAt, @Bind("absExpiresAt") Instant absExpiresAt,
            @Bind("clientIp") String clientIp, @Bind("userAgent") String userAgent,
            @Bind("uiApiKeyId") String uiApiKeyId, @Bind("uiApiKeyEnc") byte[] uiApiKeyEnc);

    @SqlQuery("SELECT " + COLUMNS + " FROM sessions WHERE id_hash = :idHash")
    Optional<Session> find(@Bind("idHash") String idHash);

    @SqlQuery("SELECT " + COLUMNS + " FROM sessions WHERE user_id = :userId AND revoked_at IS NULL")
    List<Session> findActiveByUser(@Bind("userId") String userId);

    @SqlUpdate("UPDATE sessions SET last_seen_at = :now, idle_expires_at = LEAST(:idleExpiresAt, abs_expires_at) "
            + "WHERE id_hash = :idHash AND revoked_at IS NULL")
    void touch(@Bind("idHash") String idHash, @Bind("now") Instant now, @Bind("idleExpiresAt") Instant idleExpiresAt);

    @SqlUpdate("UPDATE sessions SET revoked_at = :now WHERE id_hash = :idHash AND revoked_at IS NULL")
    int revoke(@Bind("idHash") String idHash, @Bind("now") Instant now);

    @SqlUpdate("DELETE FROM sessions WHERE abs_expires_at < :before OR revoked_at < :before")
    int purge(@Bind("before") Instant before);
}
