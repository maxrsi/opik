package com.comet.opik.auth;

import com.comet.opik.auth.config.OpikAuthConfiguration;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.dropwizard.testing.ConfigOverride;
import io.dropwizard.testing.junit5.DropwizardAppExtension;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.stream.StreamSupport;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end tests of opik-auth against a real MySQL: bootstrap, login/logout, throttling, roles, API keys and the
 * react-service protocol semantics opik-backend relies on.
 */
@ExtendWith(DropwizardExtensionsSupport.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class OpikAuthApplicationTest {

    static final String ADMIN_PASSWORD = "Bootstrap-Admin-Pass-1";
    static final String ORIGIN = "http://localhost:5173";
    static final MySQLContainer MYSQL = new MySQLContainer(DockerImageName.parse("mysql:8.4.2"))
            .withDatabaseName("opik_auth").withUsername("opik_auth").withPassword("opik_auth");

    static {
        MYSQL.start();
    }

    static final DropwizardAppExtension<OpikAuthConfiguration> APP = new DropwizardAppExtension<>(
            OpikAuthApplication.class, "config.yml",
            ConfigOverride.config("server.applicationConnectors[0].port", "0"),
            ConfigOverride.config("server.adminConnectors[0].port", "0"),
            ConfigOverride.config("database.url", MYSQL.getJdbcUrl()
                    + "?connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true"),
            ConfigOverride.config("database.user", "opik_auth"),
            ConfigOverride.config("database.password", "opik_auth"),
            ConfigOverride.config("auth.secret", "test-secret-test-secret-test-secret-123"),
            ConfigOverride.config("auth.bootstrapAdminPassword", ADMIN_PASSWORD),
            ConfigOverride.config("auth.publicOrigins", ORIGIN),
            ConfigOverride.config("auth.loginMaxFailures", "3"));

    final ObjectMapper mapper = new ObjectMapper();
    final HttpClient http = HttpClient.newHttpClient();
    String base;
    String adminSession;

    @BeforeAll
    void setUp() {
        base = "http://localhost:" + APP.getLocalPort();
    }

    // ------------------------------------------------------------------ helpers

    record Res(int status, JsonNode json, String body, HttpResponse<String> raw) {
        String sessionCookie() {
            return raw.headers().allValues("Set-Cookie").stream()
                    .filter(c -> c.startsWith("sessionToken="))
                    .map(c -> c.substring("sessionToken=".length(), c.indexOf(';')))
                    .findFirst().orElse(null);
        }
    }

    Res call(String method, String path, Object body, Map<String, String> headers) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create(base + path));
        headers.forEach(builder::header);
        if (body != null) {
            builder.header("Content-Type", "application/json");
            builder.method(method, HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }
        var response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        JsonNode json = null;
        try {
            json = response.body().isBlank() ? null : mapper.readTree(response.body());
        } catch (Exception ignored) {
            // text/plain
        }
        return new Res(response.statusCode(), json, response.body(), response);
    }

    Res session(String method, String path, String token, Object body) throws Exception {
        return call(method, path, body, Map.of("Cookie", "sessionToken=" + token, "Origin", ORIGIN));
    }

    String login(String username, String password) throws Exception {
        var res = call("POST", "/auth/api/login", Map.of("username", username, "password", password),
                Map.of("Origin", ORIGIN));
        assertThat(res.status()).as(res.body()).isEqualTo(200);
        assertThat(res.raw().headers().allValues("Set-Cookie").getFirst())
                .contains("HttpOnly").contains("SameSite=Lax").contains("Path=/");
        return res.sessionCookie();
    }

    Map<String, Object> authReq(String workspace, String... perms) {
        return perms.length == 0
                ? Map.of("workspaceName", workspace, "path", "/v1/private/x")
                : Map.of("workspaceName", workspace, "path", "/v1/private/x", "requiredPermissions", List.of(perms));
    }

    String createUser(String username, String role) throws Exception {
        var res = session("POST", "/auth/api/users", adminSession,
                Map.of("username", username, "role", role, "password", username + "-Initial0!"));
        assertThat(res.status()).as(res.body()).isEqualTo(201);
        assertThat(res.json().path("user").path("mustChangePassword").asBoolean()).isTrue();
        // admin-set passwords must be replaced before the account can use Opik
        String token = login(username, username + "-Initial0!");
        assertThat(session("POST", "/opik/auth-session", token, authReq("default")).status()).isEqualTo(403);
        var change = session("POST", "/auth/api/me/password", token,
                Map.of("currentPassword", username + "-Initial0!", "newPassword", username + "-Passw0rd!"));
        assertThat(change.status()).as(change.body()).isEqualTo(204);
        return res.json().path("user").path("id").asText();
    }

    // ------------------------------------------------------------------ tests

    @Test
    @Order(1)
    void bootstrapAdminLogsInAndMustChangePassword() throws Exception {
        var res = call("POST", "/auth/api/login", Map.of("username", "admin", "password", ADMIN_PASSWORD),
                Map.of("Origin", ORIGIN));
        assertThat(res.status()).isEqualTo(200);
        assertThat(res.json().path("mustChangePassword").asBoolean()).isTrue();
        String token = res.sessionCookie();
        assertThat(token).startsWith("ops_");

        var me = session("GET", "/auth/api/me", token, null);
        assertThat(me.status()).isEqualTo(200);
        assertThat(me.json().path("role").asText()).isEqualTo("admin");
        assertThat(me.json().path("workspaceName").asText()).isEqualTo("default");
        assertThat(me.json().path("uiApiKey").asText()).startsWith("opk_");
        assertThat(me.json().path("permissions").toString()).contains("user_manage", "workspace_write");

        // before the forced password change: no Opik access, no API keys
        var blocked = session("POST", "/opik/auth-session", token, authReq("default", "project_data_view"));
        assertThat(blocked.status()).isEqualTo(403);
        assertThat(blocked.json().path("msg").asText()).isEqualTo("Password change required");
        assertThat(call("POST", "/opik/auth", authReq("default"),
                Map.of("Authorization", me.json().path("uiApiKey").asText())).status()).isEqualTo(403);
        assertThat(session("POST", "/auth/api/me/api-keys", token, Map.of("name", "early")).status())
                .isEqualTo(403);

        var change = session("POST", "/auth/api/me/password", token,
                Map.of("currentPassword", ADMIN_PASSWORD, "newPassword", "New-Admin-Password-2"));
        assertThat(change.status()).as(change.body()).isEqualTo(204);
        var me2 = session("GET", "/auth/api/me", token, null);
        assertThat(me2.json().path("mustChangePassword").asBoolean()).isFalse();
        adminSession = token;
    }

    @Test
    @Order(2)
    void badCredentialsAndLockout() throws Exception {
        for (int i = 0; i < 3; i++) {
            var res = call("POST", "/auth/api/login", Map.of("username", "admin", "password", "wrong-password-x"),
                    Map.of("X-Forwarded-For", "10.9.9.9"));
            assertThat(res.status()).isEqualTo(401);
            assertThat(res.json().path("msg").asText()).isEqualTo("Invalid username or password");
        }
        var locked = call("POST", "/auth/api/login", Map.of("username", "admin", "password", "New-Admin-Password-2"),
                Map.of("X-Forwarded-For", "10.9.9.9"));
        assertThat(locked.status()).isEqualTo(429);
        // unknown users get the same answer as wrong passwords
        var unknown = call("POST", "/auth/api/login", Map.of("username", "nobody", "password", "whatever-123456"),
                Map.of());
        assertThat(unknown.status()).isEqualTo(401);
        assertThat(unknown.json().path("msg").asText()).isEqualTo("Invalid username or password");
    }

    @Test
    @Order(3)
    void csrfProtection() throws Exception {
        var evil = call("POST", "/auth/api/users", Map.of("username", "evil", "role", "admin"),
                Map.of("Cookie", "sessionToken=" + adminSession, "Origin", "http://evil.example"));
        assertThat(evil.status()).isEqualTo(403);
        var form = HttpRequest.newBuilder(URI.create(base + "/auth/api/users"))
                .header("Cookie", "sessionToken=" + adminSession)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("username=evil&role=admin")).build();
        assertThat(http.send(form, HttpResponse.BodyHandlers.ofString()).statusCode()).isEqualTo(415);
    }

    @Test
    @Order(4)
    void protocolSessionPathEnforcesRoles() throws Exception {
        createUser("viewer1", "viewer");
        createUser("editor1", "editor");
        createUser("annotator1", "annotator");
        String viewer = login("viewer1", "viewer1-Passw0rd!");
        String editor = login("editor1", "editor1-Passw0rd!");
        String annotator = login("annotator1", "annotator1-Passw0rd!");

        var ok = session("POST", "/opik/auth-session", viewer, authReq("default", "project_data_view"));
        assertThat(ok.status()).isEqualTo(200);
        assertThat(ok.json().path("user").asText()).isEqualTo("viewer1");
        assertThat(ok.json().path("workspaceId").asText()).isEqualTo("0190babc-62a0-71d2-832a-0feffa4676eb");
        assertThat(ok.json().path("workspaceName").asText()).isEqualTo("default");
        assertThat(ok.json().path("quotas").isArray()).isTrue();

        var noPerm = session("POST", "/opik/auth-session", viewer, authReq("default", "workspace_write"));
        assertThat(noPerm.status()).isEqualTo(403);
        assertThat(noPerm.json().path("code").asInt()).isEqualTo(403);
        assertThat(session("POST", "/opik/auth-session", viewer, authReq("DEFAULT")).status()).isEqualTo(200);

        assertThat(session("POST", "/opik/auth-session", editor,
                authReq("default", "workspace_write", "project_create", "trace_delete")).status()).isEqualTo(200);
        assertThat(session("POST", "/opik/auth-session", editor, authReq("default", "project_delete")).status())
                .isEqualTo(403);
        assertThat(session("POST", "/opik/auth-session", annotator,
                authReq("default", "trace_span_thread_annotate")).status()).isEqualTo(200);
        assertThat(session("POST", "/opik/auth-session", annotator, authReq("default", "dataset_create")).status())
                .isEqualTo(403);

        // unknown workspace → 403 (never 404), missing workspace → 400, no credential → 401
        assertThat(session("POST", "/opik/auth-session", viewer, authReq("other")).status()).isEqualTo(403);
        var missing = session("POST", "/opik/auth-session", viewer, Map.of("path", "/x"));
        assertThat(missing.status()).isEqualTo(400);
        assertThat(missing.json().path("msg").asText()).isEqualTo("Workspace name should be provided");
        var anon = call("POST", "/opik/auth-session", authReq("default"), Map.of());
        assertThat(anon.status()).isEqualTo(401);
        assertThat(anon.json().path("msg").asText()).isEqualTo("Please login first");
        assertThat(anon.raw().headers().firstValue("Content-Type").orElse("")).contains("application/json");

        // MCP OAuth path is not supported: 404 *with* the JSON envelope
        var oauth = call("POST", "/opik/auth-by-username", authReq("default"), Map.of());
        assertThat(oauth.status()).isEqualTo(404);
        assertThat(oauth.json().path("msg").isTextual()).isTrue();

        // logout invalidates immediately
        assertThat(session("POST", "/auth/api/logout", viewer, null).status()).isEqualTo(204);
        assertThat(session("POST", "/opik/auth-session", viewer, authReq("default")).status()).isEqualTo(401);
    }

    @Test
    @Order(5)
    void apiKeysInheritOwnerRoleAndCanBeRevoked() throws Exception {
        String viewer = login("viewer1", "viewer1-Passw0rd!");
        var created = session("POST", "/auth/api/me/api-keys", viewer, Map.of("name", "sdk"));
        assertThat(created.status()).isEqualTo(201);
        String key = created.json().path("key").asText();
        String keyId = created.json().path("id").asText();
        assertThat(key).startsWith("opk_").doesNotContain("*");

        var ok = call("POST", "/opik/auth", authReq("default", "project_data_view"), Map.of("Authorization", key));
        assertThat(ok.status()).isEqualTo(200);
        assertThat(ok.json().path("user").asText()).isEqualTo("viewer1");
        assertThat(call("POST", "/opik/auth", authReq("default", "workspace_write"), Map.of("Authorization", key))
                .status()).isEqualTo(403);
        assertThat(call("POST", "/opik/auth", authReq("default"), Map.of("Authorization", "opk_bogus")).status())
                .isEqualTo(401);

        var perms = call("POST", "/opik/workspace-permissions", Map.of("workspaceName", "default"),
                Map.of("Authorization", key));
        assertThat(perms.status()).isEqualTo(200);
        assertThat(perms.json().path("userName").asText()).isEqualTo("viewer1");
        var names = StreamSupport.stream(perms.json().path("permissions").spliterator(), false)
                .map(p -> p.path("permissionName").asText() + "=" + p.path("permissionValue").asText()).toList();
        assertThat(names).contains("project_data_view=true").doesNotContain("workspace_write=true");

        // listing never returns the secret
        var list = session("GET", "/auth/api/me/api-keys", viewer, null);
        assertThat(list.body()).doesNotContain(key).contains(keyId);

        assertThat(session("DELETE", "/auth/api/me/api-keys/" + keyId, viewer, null).status()).isEqualTo(204);
        assertThat(call("POST", "/opik/auth", authReq("default"), Map.of("Authorization", key)).status())
                .isEqualTo(401);
    }

    @Test
    @Order(6)
    void sessionTokenAcceptedAsAuthorizationForPermissions() throws Exception {
        // RemoteAuthService stores the session token in RequestContext.apiKey and WorkspacePermissionsResource
        // forwards it as Authorization to /opik/workspace-permissions.
        String editor = login("editor1", "editor1-Passw0rd!");
        var perms = call("POST", "/opik/workspace-permissions", Map.of("workspaceName", "default"),
                Map.of("Authorization", editor));
        assertThat(perms.status()).isEqualTo(200);
        assertThat(perms.body()).contains("workspace_write").doesNotContain("user_manage");
        var bySession = session("POST", "/opik/workspace-permissions-session", editor,
                Map.of("workspaceName", "default"));
        assertThat(bySession.status()).isEqualTo(200);

        var ws = session("GET", "/workspaces?withoutExtendedData=true", editor, null);
        assertThat(ws.status()).isEqualTo(200);
        assertThat(ws.json().get(0).path("workspaceName").asText()).isEqualTo("default");
        assertThat(ws.json().get(0).path("default").asBoolean()).isTrue();
        var id = call("GET", "/workspaces/workspace-id?name=default", null, Map.of());
        assertThat(id.body()).isEqualTo("0190babc-62a0-71d2-832a-0feffa4676eb");
        var name = call("GET", "/workspaces/workspace-name?id=0190babc-62a0-71d2-832a-0feffa4676eb", null, Map.of());
        assertThat(name.body()).isEqualTo("default");
    }

    @Test
    @Order(7)
    void sessionUiKeyIsUsableAndDiesWithSession() throws Exception {
        String editor = login("editor1", "editor1-Passw0rd!");
        String uiKey = session("GET", "/auth/api/me", editor, null).json().path("uiApiKey").asText();
        assertThat(call("POST", "/opik/auth", authReq("default", "optimization_studio_use"),
                Map.of("Authorization", uiKey)).status()).isEqualTo(200);
        session("POST", "/auth/api/logout", editor, null);
        assertThat(call("POST", "/opik/auth", authReq("default"), Map.of("Authorization", uiKey)).status())
                .isEqualTo(401);
    }

    @Test
    @Order(8)
    void adminGuardsAndRoleChanges() throws Exception {
        String viewer = login("viewer1", "viewer1-Passw0rd!");
        assertThat(session("GET", "/auth/api/users", viewer, null).status()).isEqualTo(403);
        assertThat(session("GET", "/auth/api/audit-logs", viewer, null).status()).isEqualTo(403);

        var users = session("GET", "/auth/api/users", adminSession, null);
        String adminId = StreamSupport.stream(users.json().spliterator(), false)
                .filter(u -> u.path("username").asText().equals("admin")).findFirst().orElseThrow()
                .path("id").asText();
        var demote = session("PATCH", "/auth/api/users/" + adminId, adminSession, Map.of("role", "viewer"));
        assertThat(demote.status()).isEqualTo(409);

        // promote viewer1 to editor: takes effect for the existing session
        String viewerId = StreamSupport.stream(users.json().spliterator(), false)
                .filter(u -> u.path("username").asText().equals("viewer1")).findFirst().orElseThrow()
                .path("id").asText();
        var promote = session("PATCH", "/auth/api/users/" + viewerId, adminSession, Map.of("role", "editor"));
        assertThat(promote.status()).isEqualTo(200);
        assertThat(promote.json().path("roleId").asText()).isEqualTo("editor");
        assertThat(session("POST", "/opik/auth-session", viewer, authReq("default", "workspace_write")).status())
                .isEqualTo(200);

        // disabling revokes sessions
        var disable = session("PATCH", "/auth/api/users/" + viewerId, adminSession, Map.of("status", "disabled"));
        assertThat(disable.status()).isEqualTo(200);
        assertThat(session("POST", "/opik/auth-session", viewer, authReq("default")).status()).isEqualTo(401);
        var relogin = call("POST", "/auth/api/login", Map.of("username", "viewer1", "password", "viewer1-Passw0rd!"),
                Map.of());
        assertThat(relogin.status()).isEqualTo(401);

        // reset password returns a one-time random password and forces a change
        var reset = session("POST", "/auth/api/users/" + viewerId + "/reset-password", adminSession, null);
        assertThat(reset.status()).isEqualTo(200);
        session("PATCH", "/auth/api/users/" + viewerId, adminSession, Map.of("status", "active"));
        var afterReset = call("POST", "/auth/api/login",
                Map.of("username", "viewer1", "password", reset.json().path("password").asText()), Map.of());
        assertThat(afterReset.status()).isEqualTo(200);
        assertThat(afterReset.json().path("mustChangePassword").asBoolean()).isTrue();

        var roles = session("GET", "/auth/api/roles", adminSession, null);
        assertThat(roles.json().size()).isEqualTo(4);

        // audit storage disabled in this test → explicit 503
        assertThat(session("GET", "/auth/api/audit-logs", adminSession, null).status()).isEqualTo(503);
    }
}
