package com.comet.opik.auth.db;

import com.comet.opik.auth.db.Records.LoginAttempt;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Instant;
import java.util.Optional;

@RegisterConstructorMapper(LoginAttempt.class)
public interface LoginAttemptDao {

    @SqlQuery("SELECT subject, client_ip, failed_count, locked_until, last_failed_at FROM login_attempts "
            + "WHERE subject = :subject AND client_ip = :clientIp")
    Optional<LoginAttempt> find(@Bind("subject") String subject, @Bind("clientIp") String clientIp);

    @SqlUpdate("INSERT INTO login_attempts (subject, client_ip, failed_count, locked_until, last_failed_at) "
            + "VALUES (:subject, :clientIp, :failedCount, :lockedUntil, :now) "
            + "ON DUPLICATE KEY UPDATE failed_count = VALUES(failed_count), locked_until = VALUES(locked_until), "
            + "last_failed_at = VALUES(last_failed_at)")
    void upsert(@Bind("subject") String subject, @Bind("clientIp") String clientIp,
            @Bind("failedCount") int failedCount, @Bind("lockedUntil") Instant lockedUntil, @Bind("now") Instant now);

    @SqlUpdate("DELETE FROM login_attempts WHERE subject = :subject AND client_ip = :clientIp")
    void clear(@Bind("subject") String subject, @Bind("clientIp") String clientIp);
}
