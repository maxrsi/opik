# opik-auth

Self-hosted authentication / RBAC service for Opik. It implements the "react-service" protocol that
`opik-backend` calls when `authentication.enabled=true` (`RemoteAuthService`, `RemoteWorkspacePermissionsService`),
plus a small public API used by the frontend `selfhosted` plugin.

Stack mirrors `apps/opik-backend`: Java 25, Dropwizard 5.0.2, JDBI3, Liquibase (dropwizard-migrations), MySQL
(own database `opik_auth`), argon2id via BouncyCastle.

## Endpoints

Internal protocol (NOT routed by nginx):

| Endpoint | Credential |
|---|---|
| `POST /opik/auth` | `Authorization: <API key or session token>` |
| `POST /opik/auth-session` | Cookie `sessionToken` |
| `POST /opik/workspace-permissions` | `Authorization: <API key or session token>` |
| `POST /opik/workspace-permissions-session` | Cookie `sessionToken` |
| `POST /opik/auth-by-username`, `/opik/workspace-permissions-by-username` | 404 (MCP OAuth not supported) |
| `GET /workspaces`, `/workspaces/workspace-id?name=`, `/workspaces/workspace-name?id=` | |

Public API (`/auth/api/*`, cookie session): `login`, `logout`, `me`, `me/password`, `me/api-keys`,
`users` (Admin), `users/{id}/reset-password` (Admin), `roles`, `api-keys` (Admin), `audit-logs` (Admin).

## Built-in roles

`admin`, `editor`, `annotator`, `viewer` — seeded by `000002_seed_builtin_roles.sql`. API keys inherit the owner's
role (optionally narrowed by `api_keys.role_id`).

## First admin

On startup, if `users` is empty, a user `OPIK_AUTH_BOOTSTRAP_ADMIN_USERNAME` (default `admin`) is created with
`OPIK_AUTH_BOOTSTRAP_ADMIN_PASSWORD`, or with a random password printed once in the log
(`=== Initial admin password ...`). The password must be changed at first login.

Recovery: `docker compose exec opik-auth java -jar opik-auth.jar reset-admin-password config.yml --username admin`

## Build / test

```bash
mvn clean package          # tests need Docker (Testcontainers MySQL)
java -jar target/opik-auth.jar server config.yml
```

See `config.yml` for all `OPIK_AUTH_*` environment variables.

## Running the full stack (docker compose)

```bash
cd deployment/docker-compose
export OPIK_AUTH_SECRET=$(openssl rand -base64 48)            # required; keep it stable
export OPIK_AUTH_BOOTSTRAP_ADMIN_PASSWORD='choose-a-long-one'  # optional (else random, printed once in the log)
docker compose -f docker-compose.yaml -f docker-compose.auth.yaml --profile opik up -d --build
# UI: http://localhost:5173  → log in as admin, set a new password
docker compose -f docker-compose.yaml -f docker-compose.auth.yaml logs opik-auth | grep 'Initial admin'
```

SDK: create a key under *My API keys*, then `OPIK_URL_OVERRIDE=http://localhost:5173/api OPIK_API_KEY=<key>
OPIK_WORKSPACE=default`.

## Smoke tests

`e2e/smoke.sh` (curl: login, roles, API keys, revocation, audit rows in ClickHouse) and `e2e/ui.mjs` (headless
browser: login page, menus, admin pages, Viewer/Editor buttons) run against a fresh compose stack.
