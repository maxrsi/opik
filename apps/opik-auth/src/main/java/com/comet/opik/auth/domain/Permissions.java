package com.comet.opik.auth.domain;

/** opik-auth specific permission strings (the rest are opik-backend WorkspaceUserPermission values). */
public final class Permissions {

    /** Fallback permission opik-backend requires for write endpoints without @RequiredPermissions. */
    public static final String WORKSPACE_WRITE = "workspace_write";
    public static final String USER_MANAGE = "user_manage";
    public static final String AUDIT_LOG_VIEW = "audit_log_view";

    private Permissions() {
    }
}
