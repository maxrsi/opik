package com.comet.opik.auth.db;

import com.comet.opik.auth.db.Records.Role;
import com.comet.opik.auth.db.Records.Workspace;
import org.jdbi.v3.sqlobject.config.RegisterConstructorMapper;
import org.jdbi.v3.sqlobject.customizer.Bind;
import org.jdbi.v3.sqlobject.statement.SqlQuery;
import org.jdbi.v3.sqlobject.statement.SqlUpdate;

import java.util.List;
import java.util.Optional;

@RegisterConstructorMapper(Role.class)
@RegisterConstructorMapper(Workspace.class)
public interface RbacDao {

    @SqlQuery("SELECT id, name, is_default FROM workspaces WHERE LOWER(name) = LOWER(:name)")
    Optional<Workspace> findWorkspaceByName(@Bind("name") String name);

    @SqlQuery("SELECT id, name, is_default FROM workspaces WHERE id = :id")
    Optional<Workspace> findWorkspaceById(@Bind("id") String id);

    @SqlQuery("SELECT w.id, w.name, w.is_default FROM workspaces w "
            + "JOIN workspace_members m ON m.workspace_id = w.id WHERE m.user_id = :userId ORDER BY w.name")
    List<Workspace> findWorkspacesOfUser(@Bind("userId") String userId);

    @SqlQuery("SELECT id, display_name, description, builtin, sort_order FROM roles ORDER BY sort_order")
    List<Role> listRoles();

    @SqlQuery("SELECT id, display_name, description, builtin, sort_order FROM roles WHERE id = :id")
    Optional<Role> findRole(@Bind("id") String id);

    @SqlQuery("SELECT permission FROM role_permissions WHERE role_id = :roleId ORDER BY permission")
    List<String> permissionsOfRole(@Bind("roleId") String roleId);

    @SqlQuery("SELECT role_id FROM workspace_members WHERE workspace_id = :workspaceId AND user_id = :userId")
    Optional<String> roleOf(@Bind("workspaceId") String workspaceId, @Bind("userId") String userId);

    @SqlUpdate("INSERT INTO workspace_members (workspace_id, user_id, role_id, created_by, last_updated_by) "
            + "VALUES (:workspaceId, :userId, :roleId, :by, :by) "
            + "ON DUPLICATE KEY UPDATE role_id = VALUES(role_id), last_updated_by = VALUES(last_updated_by)")
    void upsertMember(@Bind("workspaceId") String workspaceId, @Bind("userId") String userId,
            @Bind("roleId") String roleId, @Bind("by") String by);

    @SqlQuery("SELECT COUNT(*) FROM workspace_members m JOIN users u ON u.id = m.user_id "
            + "WHERE m.workspace_id = :workspaceId AND m.role_id = 'admin' AND u.status = 'active'")
    long countActiveAdmins(@Bind("workspaceId") String workspaceId);
}
