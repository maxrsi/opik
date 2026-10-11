package com.comet.opik.infrastructure.auth;

import com.comet.opik.api.resources.utils.MySQLContainerUtils;
import com.comet.opik.api.resources.utils.TestHttpClientUtils;
import com.comet.opik.domain.ProjectService;
import com.comet.opik.domain.RemoteWorkspacePermissionsService;
import com.comet.opik.infrastructure.AuthenticationConfig;
import com.comet.opik.infrastructure.RetriableHttpClient;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.Cookie;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.mysql.MySQLContainer;

import java.io.File;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Fork-only contract test: the real {@link RemoteAuthService} / {@link RemoteWorkspacePermissionsService} against a
 * real opik-auth (apps/opik-auth) process backed by MySQL. Proves the protocol shapes and error semantics the
 * backend relies on, without WireMock stubs.
 * <p>
 * Needs Docker and the opik-auth jar: {@code mvn -f ../opik-auth package -DskipTests} (or pass
 * {@code -Dopik.auth.jar=/path/opik-auth.jar}). Skipped when the jar is absent.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RemoteAuthServiceOpikAuthContractTest {

    private static final String ADMIN_PASSWORD = "Contract-Admin-Pass-1";
    private static final String DEFAULT_WS = ProjectService.DEFAULT_WORKSPACE_NAME;
    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient http = HttpClient.newHttpClient();

    private MySQLContainer mysql;
    private Process opikAuth;
    private String baseUrl;
    private RequestContext requestContext;
    private RemoteAuthService service;
    private RemoteAuthService serviceWithoutDefaultWorkspaceFlag;
    private RemoteWorkspacePermissionsService permissionsService;

    private String viewerSession;
    private String editorSession;
    private String viewerApiKey;

    @BeforeAll
    void setUp() throws Exception {
        Path jar = Path.of(System.getProperty("opik.auth.jar", "../opik-auth/target/opik-auth.jar"));
        Assumptions.assumeTrue(Files.exists(jar), "opik-auth jar not built: " + jar.toAbsolutePath());

        mysql = MySQLContainerUtils.newMySQLContainer(false);
        mysql.start();

        int port = freePort();
        int adminPort = freePort();
        baseUrl = "http://localhost:" + port;
        var pb = new ProcessBuilder("java", "-jar", jar.toAbsolutePath().toString(), "server",
                jar.toAbsolutePath().getParent().getParent().resolve("config.yml").toString());
        pb.environment().putAll(Map.of(
                "OPIK_AUTH_PORT", String.valueOf(port),
                "OPIK_AUTH_ADMIN_PORT", String.valueOf(adminPort),
                "OPIK_AUTH_DB_URL", mysql.getJdbcUrl(),
                "OPIK_AUTH_DB_USER", mysql.getUsername(),
                "OPIK_AUTH_DB_PASS", mysql.getPassword(),
                "OPIK_AUTH_SECRET", "contract-test-secret-contract-test-secret",
                "OPIK_AUTH_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PASSWORD,
                "OPIK_AUTH_PUBLIC_ORIGIN", ""));
        pb.redirectErrorStream(true).redirectOutput(new File("target/opik-auth-contract.log"));
        opikAuth = pb.start();
        waitUntilUp();

        String admin = login("admin", ADMIN_PASSWORD);
        createUser(admin, "contract-viewer", "viewer");
        createUser(admin, "contract-editor", "editor");
        viewerSession = login("contract-viewer", "contract-viewer-Passw0rd!");
        editorSession = login("contract-editor", "contract-editor-Passw0rd!");
        viewerApiKey = post("/auth/api/me/api-keys", Map.of("name", "contract"), viewerSession).path("key").asText();

        var client = TestHttpClientUtils.client();
        var url = new AuthenticationConfig.UrlConfig(baseUrl);
        permissionsService = new RemoteWorkspacePermissionsService(client, url);
        service = new RemoteAuthService(client, new RetriableHttpClient(client), url, () -> requestContext,
                new NoopCacheService(), Duration.ofSeconds(3), 0, Duration.ofMillis(10), Duration.ofMillis(20),
                permissionsService, true, true);
        serviceWithoutDefaultWorkspaceFlag = new RemoteAuthService(client, new RetriableHttpClient(client), url,
                () -> requestContext, new NoopCacheService(), Duration.ofSeconds(3), 0, Duration.ofMillis(10),
                Duration.ofMillis(20), permissionsService, true);
    }

    @AfterAll
    void tearDown() {
        if (opikAuth != null) {
            opikAuth.destroy();
        }
        if (mysql != null) {
            mysql.stop();
        }
    }

    @BeforeEach
    void resetContext() {
        requestContext = new RequestContext();
    }

    // ------------------------------------------------------------------ session path

    @Test
    void sessionForDefaultWorkspaceIsAcceptedWhenFlagIsOn() {
        service.authenticate(headers(DEFAULT_WS, null), new Cookie("sessionToken", viewerSession),
                context("/v1/private/projects", WorkspaceUserPermission.PROJECT_DATA_VIEW.getValue()));

        assertThat(requestContext.getUserName()).isEqualTo("contract-viewer");
        assertThat(requestContext.getWorkspaceId()).isEqualTo(ProjectService.DEFAULT_WORKSPACE_ID);
        assertThat(requestContext.getWorkspaceName()).isEqualTo(DEFAULT_WS);
        assertThat(requestContext.getQuotas()).isEmpty();
        assertThat(requestContext.getApiKey()).isEqualTo(viewerSession);
        // resolvePermissions=true: permissions come from /opik/workspace-permissions-session
        assertThat(requestContext.getPermissions()).contains("project_data_view").doesNotContain("workspace_write");
    }

    @Test
    void sessionForDefaultWorkspaceIsRejectedWhenFlagIsOff() {
        assertThatThrownBy(() -> serviceWithoutDefaultWorkspaceFlag.authenticate(headers(DEFAULT_WS, null),
                new Cookie("sessionToken", viewerSession), context("/v1/private/projects")))
                .isInstanceOf(ClientErrorException.class)
                .satisfies(e -> assertThat(((ClientErrorException) e).getResponse().getStatus()).isEqualTo(403));
    }

    @Test
    void viewerIsDeniedWritesEditorIsAllowed() {
        assertStatus(() -> service.authenticate(headers(DEFAULT_WS, null), new Cookie("sessionToken", viewerSession),
                context("/v1/private/projects", "workspace_write")), 403);
        assertStatus(() -> service.authenticate(headers(DEFAULT_WS, null), new Cookie("sessionToken", viewerSession),
                context("/v1/private/projects", WorkspaceUserPermission.PROJECT_CREATE.getValue())), 403);

        service.authenticate(headers(DEFAULT_WS, null), new Cookie("sessionToken", editorSession),
                context("/v1/private/projects", "workspace_write",
                        WorkspaceUserPermission.PROJECT_CREATE.getValue()));
        assertThat(requestContext.getUserName()).isEqualTo("contract-editor");
    }

    @Test
    void invalidSessionIs401WithMessage() {
        assertThatThrownBy(() -> service.authenticate(headers(DEFAULT_WS, null),
                new Cookie("sessionToken", "ops_invalid"), context("/v1/private/projects")))
                .isInstanceOf(ClientErrorException.class)
                .satisfies(e -> {
                    assertThat(((ClientErrorException) e).getResponse().getStatus()).isEqualTo(401);
                    assertThat(e.getMessage()).isEqualTo("Please login first");
                });
    }

    @Test
    void unknownWorkspaceIs403NotServerError() {
        assertStatus(() -> service.authenticate(headers("some-other-workspace", null),
                new Cookie("sessionToken", viewerSession), context("/v1/private/projects")), 403);
    }

    // ------------------------------------------------------------------ API key path

    @Test
    void apiKeyInheritsOwnerRole() {
        service.authenticate(headers(DEFAULT_WS, viewerApiKey), null,
                context("/v1/private/traces/search", WorkspaceUserPermission.PROJECT_DATA_VIEW.getValue()));
        assertThat(requestContext.getUserName()).isEqualTo("contract-viewer");
        assertThat(requestContext.getApiKey()).isEqualTo(viewerApiKey);

        resetContext();
        assertStatus(() -> service.authenticate(headers(DEFAULT_WS, viewerApiKey), null,
                context("/v1/private/traces", WorkspaceUserPermission.TRACE_SPAN_THREAD_LOG.getValue())), 403);
        assertStatus(() -> service.authenticate(headers(DEFAULT_WS, "opk_doesnotexist"), null,
                context("/v1/private/traces")), 401);
    }

    // ------------------------------------------------------------------ permissions API

    @Test
    void workspacePermissionsAcceptSessionTokenAsAuthorization() {
        // WorkspacePermissionsResource passes RequestContext.apiKey, which holds the session token for browsers.
        var permissions = permissionsService.getPermissions(editorSession, DEFAULT_WS);
        assertThat(permissions.userName()).isEqualTo("contract-editor");
        assertThat(permissions.workspaceName()).isEqualTo(DEFAULT_WS);
        assertThat(permissions.permissions())
                .extracting(p -> p.permissionName() + "=" + p.permissionValue())
                .contains("workspace_write=true", "project_create=true")
                .doesNotContain("workspace_settings_configure=true");

        var byKey = permissionsService.getPermissions(viewerApiKey, DEFAULT_WS);
        assertThat(byKey.permissions()).extracting(p -> p.permissionName())
                .contains("project_data_view").doesNotContain("workspace_write");
    }

    @Test
    void workspaceListingForSession() {
        var workspaces = service.listEligibleWorkspaces(new Cookie("sessionToken", viewerSession));
        // RemoteAuthService filters 'default' out of the MCP consent list by design
        assertThat(workspaces).isEmpty();
    }

    // ------------------------------------------------------------------ helpers

    private void assertStatus(Runnable call, int status) {
        assertThatThrownBy(call::run).isInstanceOf(ClientErrorException.class)
                .satisfies(e -> assertThat(((ClientErrorException) e).getResponse().getStatus()).isEqualTo(status));
    }

    private static HttpHeaders headers(String workspace, String apiKey) {
        var headers = mock(HttpHeaders.class);
        when(headers.getHeaderString(RequestContext.WORKSPACE_HEADER)).thenReturn(workspace);
        when(headers.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(apiKey);
        return headers;
    }

    private static ContextInfoHolder context(String path, String... permissions) {
        var uriInfo = mock(UriInfo.class);
        when(uriInfo.getRequestUri()).thenReturn(URI.create(path));
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        return ContextInfoHolder.builder().uriInfo(uriInfo).method("POST")
                .requiredPermissions(List.of(permissions)).build();
    }

    private void waitUntilUp() throws Exception {
        long deadline = System.currentTimeMillis() + 120_000;
        while (System.currentTimeMillis() < deadline) {
            if (!opikAuth.isAlive()) {
                throw new IllegalStateException("opik-auth exited, see target/opik-auth-contract.log");
            }
            try {
                var res = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/auth/api/me")).GET().build(),
                        HttpResponse.BodyHandlers.discarding());
                if (res.statusCode() == 401) {
                    return;
                }
            } catch (Exception ignored) {
                // not up yet
            }
            Thread.sleep(500);
        }
        throw new IllegalStateException("opik-auth did not start in time");
    }

    private String login(String username, String password) throws Exception {
        var res = http.send(HttpRequest.newBuilder(URI.create(baseUrl + "/auth/api/login"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(
                        Map.of("username", username, "password", password))))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(res.statusCode()).as(res.body()).isEqualTo(200);
        String cookie = res.headers().firstValue("Set-Cookie").orElseThrow();
        return cookie.substring("sessionToken=".length(), cookie.indexOf(';'));
    }

    private void createUser(String adminSession, String username, String role) throws Exception {
        post("/auth/api/users", Map.of("username", username, "role", role, "password", username + "-Initial0!"),
                adminSession);
        // admin-set passwords must be changed before opik-auth lets the account use Opik
        post("/auth/api/me/password", Map.of("currentPassword", username + "-Initial0!",
                "newPassword", username + "-Passw0rd!"), login(username, username + "-Initial0!"));
    }

    private JsonNode post(String path, Object body, String session) throws Exception {
        var res = http.send(HttpRequest.newBuilder(URI.create(baseUrl + path))
                .header("Content-Type", "application/json")
                .header("Cookie", "sessionToken=" + session)
                .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(res.statusCode()).as(res.body()).isBetween(200, 299);
        return mapper.readTree(res.body());
    }

    private static int freePort() throws Exception {
        try (var socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
