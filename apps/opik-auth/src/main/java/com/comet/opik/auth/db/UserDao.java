package com.comet.opik.auth.db;

import com.comet.opik.auth.db.Records.Identity;
import com.comet.opik.auth.db.Records.User;
import com.comet.opik.auth.db.Records.UserWithRole;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@RegisterConstructorMapper(User.class)
@RegisterConstructorMapper(UserWithRole.class)
@RegisterConstructorMapper(Identity.class)
public interface UserDao {

    String USER_COLUMNS = "u.id, u.username, u.display_name, u.email, u.status, u.user_type, u.must_change_password, "
            + "u.created_at, u.created_by, u.last_login_at";

    @SqlQuery("SELECT COUNT(*) FROM users")
    long countUsers();

    @SqlQuery("SELECT " + USER_COLUMNS + " FROM users u WHERE u.id = :id")
    Optional<User> findById(@Bind("id") String id);

    @SqlQuery("SELECT " + USER_COLUMNS + " FROM users u WHERE LOWER(u.username) = LOWER(:username)")
    Optional<User> findByUsername(@Bind("username") String username);

    @SqlQuery("SELECT " + USER_COLUMNS + ", m.role_id FROM users u "
            + "LEFT JOIN workspace_members m ON m.user_id = u.id AND m.workspace_id = :workspaceId "
            + "ORDER BY u.username")
    List<UserWithRole> listWithRole(@Bind("workspaceId") String workspaceId);

    @SqlQuery("SELECT " + USER_COLUMNS + ", m.role_id FROM users u "
            + "LEFT JOIN workspace_members m ON m.user_id = u.id AND m.workspace_id = :workspaceId WHERE u.id = :id")
    Optional<UserWithRole> findWithRole(@Bind("workspaceId") String workspaceId, @Bind("id") String id);

    @SqlUpdate("INSERT INTO users (id, username, display_name, email, status, user_type, must_change_password, created_by) "
            + "VALUES (:id, :username, :displayName, :email, 'active', :userType, :mustChangePassword, :createdBy)")
    void insert(@Bind("id") String id, @Bind("username") String username, @Bind("displayName") String displayName,
            @Bind("email") String email, @Bind("userType") String userType,
            @Bind("mustChangePassword") boolean mustChangePassword, @Bind("createdBy") String createdBy);

    @SqlUpdate("UPDATE users SET display_name = :displayName, email = :email WHERE id = :id")
    void updateProfile(@Bind("id") String id, @Bind("displayName") String displayName, @Bind("email") String email);

    @SqlUpdate("UPDATE users SET status = :status WHERE id = :id")
    void updateStatus(@Bind("id") String id, @Bind("status") String status);

    @SqlUpdate("UPDATE users SET must_change_password = :value WHERE id = :id")
    void setMustChangePassword(@Bind("id") String id, @Bind("value") boolean value);

    @SqlUpdate("UPDATE users SET last_login_at = :now WHERE id = :id")
    void touchLogin(@Bind("id") String id, @Bind("now") Instant now);

    // ---- identities ----

    @SqlQuery("SELECT id, user_id, provider, subject, secret_hash FROM user_identities "
            + "WHERE provider = :provider AND subject = :subject")
    Optional<Identity> findIdentity(@Bind("provider") String provider, @Bind("subject") String subject);

    @SqlQuery("SELECT id, user_id, provider, subject, secret_hash FROM user_identities "
            + "WHERE user_id = :userId AND provider = :provider")
    Optional<Identity> findIdentityByUser(@Bind("userId") String userId, @Bind("provider") String provider);

    @SqlUpdate("INSERT INTO user_identities (id, user_id, provider, subject, secret_hash, password_changed_at) "
            + "VALUES (:id, :userId, :provider, :subject, :secretHash, :now)")
    void insertIdentity(@Bind("id") String id, @Bind("userId") String userId, @Bind("provider") String provider,
            @Bind("subject") String subject, @Bind("secretHash") String secretHash, @Bind("now") Instant now);

    @SqlUpdate("UPDATE user_identities SET secret_hash = :secretHash, password_changed_at = :now "
            + "WHERE user_id = :userId AND provider = 'local'")
    int updateLocalSecret(@Bind("userId") String userId, @Bind("secretHash") String secretHash,
            @Bind("now") Instant now);

    @SqlUpdate("UPDATE user_identities SET last_used_at = :now WHERE id = :id")
    void touchIdentity(@Bind("id") String id, @Bind("now") Instant now);
}
