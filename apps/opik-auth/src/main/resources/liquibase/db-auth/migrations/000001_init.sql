--liquibase formatted sql
--changeset opik-auth:000001_init

CREATE TABLE users (
    id                   CHAR(36)     NOT NULL PRIMARY KEY,
    username             VARCHAR(100) NOT NULL,
    display_name         VARCHAR(255) NULL,
    email                VARCHAR(255) NULL,
    status               ENUM('active','disabled') NOT NULL DEFAULT 'active',
    user_type            ENUM('human','service')   NOT NULL DEFAULT 'human',
    must_change_password BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at           TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    created_by           VARCHAR(100) NOT NULL DEFAULT 'system',
    last_updated_at      TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    last_login_at        TIMESTAMP(6) NULL,
    CONSTRAINT users_username_uk UNIQUE (username),
    CONSTRAINT users_email_uk UNIQUE (email)
);

-- Identities: the local password is one identity (provider='local'); a future OIDC login is another
-- (provider='oidc:<alias>', subject=sub) pointing at the same user. No schema change needed for SSO.
CREATE TABLE user_identities (
    id                  CHAR(36)     NOT NULL PRIMARY KEY,
    user_id             CHAR(36)     NOT NULL,
    provider            VARCHAR(100) NOT NULL,
    subject             VARCHAR(255) NOT NULL,
    secret_hash         VARCHAR(255) NULL,
    password_changed_at TIMESTAMP(6) NULL,
    profile_json        JSON         NULL,
    created_at          TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_used_at        TIMESTAMP(6) NULL,
    CONSTRAINT user_identities_provider_subject_uk UNIQUE (provider, subject),
    CONSTRAINT user_identities_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    INDEX user_identities_user_idx (user_id)
);

CREATE TABLE workspaces (
    id         CHAR(36)     NOT NULL PRIMARY KEY,
    name       VARCHAR(150) NOT NULL,
    is_default BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT workspaces_name_uk UNIQUE (name)
);

-- Same id/name as opik-backend ProjectService.DEFAULT_WORKSPACE_ID / DEFAULT_WORKSPACE_NAME: no data migration.
INSERT INTO workspaces (id, name, is_default) VALUES ('0190babc-62a0-71d2-832a-0feffa4676eb', 'default', TRUE);

CREATE TABLE roles (
    id           VARCHAR(50)  NOT NULL PRIMARY KEY,
    display_name VARCHAR(100) NOT NULL,
    description  VARCHAR(500) NULL,
    builtin      BOOLEAN      NOT NULL DEFAULT TRUE,
    sort_order   INT          NOT NULL DEFAULT 0
);

CREATE TABLE role_permissions (
    role_id    VARCHAR(50)  NOT NULL,
    permission VARCHAR(100) NOT NULL,
    PRIMARY KEY (role_id, permission),
    CONSTRAINT role_permissions_role_fk FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

CREATE TABLE workspace_members (
    workspace_id    CHAR(36)     NOT NULL,
    user_id         CHAR(36)     NOT NULL,
    role_id         VARCHAR(50)  NOT NULL,
    created_at      TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    created_by      VARCHAR(100) NOT NULL,
    last_updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    last_updated_by VARCHAR(100) NOT NULL,
    PRIMARY KEY (workspace_id, user_id),
    CONSTRAINT wm_ws_fk FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    CONSTRAINT wm_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT wm_role_fk FOREIGN KEY (role_id) REFERENCES roles (id)
);

CREATE TABLE sessions (
    id_hash         CHAR(64)       NOT NULL PRIMARY KEY,
    user_id         CHAR(36)       NOT NULL,
    created_at      TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen_at    TIMESTAMP(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    idle_expires_at TIMESTAMP(6)   NOT NULL,
    abs_expires_at  TIMESTAMP(6)   NOT NULL,
    revoked_at      TIMESTAMP(6)   NULL,
    client_ip       VARCHAR(64)    NULL,
    user_agent      VARCHAR(512)   NULL,
    ui_api_key_id   CHAR(36)       NULL,
    ui_api_key_enc  VARBINARY(512) NULL,
    CONSTRAINT sessions_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    INDEX sessions_user_idx (user_id),
    INDEX sessions_expiry_idx (abs_expires_at)
);

CREATE TABLE api_keys (
    id           CHAR(36)     NOT NULL PRIMARY KEY,
    user_id      CHAR(36)     NOT NULL,
    workspace_id CHAR(36)     NOT NULL,
    name         VARCHAR(100) NOT NULL,
    key_prefix   CHAR(8)      NOT NULL,
    key_hash     CHAR(64)     NOT NULL,
    kind         ENUM('personal','session') NOT NULL DEFAULT 'personal',
    role_id      VARCHAR(50)  NULL,
    created_at   TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at   TIMESTAMP(6) NULL,
    last_used_at TIMESTAMP(6) NULL,
    revoked_at   TIMESTAMP(6) NULL,
    revoked_by   VARCHAR(100) NULL,
    CONSTRAINT api_keys_prefix_uk UNIQUE (key_prefix),
    CONSTRAINT api_keys_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT api_keys_ws_fk FOREIGN KEY (workspace_id) REFERENCES workspaces (id),
    CONSTRAINT api_keys_role_fk FOREIGN KEY (role_id) REFERENCES roles (id),
    INDEX api_keys_user_idx (user_id)
);

CREATE TABLE login_attempts (
    subject        VARCHAR(255) NOT NULL,
    client_ip      VARCHAR(64)  NOT NULL,
    failed_count   INT          NOT NULL DEFAULT 0,
    locked_until   TIMESTAMP(6) NULL,
    last_failed_at TIMESTAMP(6) NULL,
    PRIMARY KEY (subject, client_ip)
);

--rollback DROP TABLE login_attempts; DROP TABLE api_keys; DROP TABLE sessions; DROP TABLE workspace_members; DROP TABLE role_permissions; DROP TABLE roles; DROP TABLE workspaces; DROP TABLE user_identities; DROP TABLE users;
