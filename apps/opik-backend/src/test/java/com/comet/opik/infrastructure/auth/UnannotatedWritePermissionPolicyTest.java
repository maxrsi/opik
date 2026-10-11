package com.comet.opik.infrastructure.auth;

import com.comet.opik.infrastructure.AuthenticationConfig;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.container.ResourceInfo;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class UnannotatedWritePermissionPolicyTest {

    static class SampleResource {
        @POST
        public void create() {
        }

        @PATCH
        @RequiredPermissions(WorkspaceUserPermission.PROJECT_CREATE)
        public void annotated() {
        }

        @GET
        public void read() {
        }

        @DELETE
        public void exempted() {
        }
    }

    private static ResourceInfo info(String methodName) throws NoSuchMethodException {
        Method method = SampleResource.class.getMethod(methodName);
        return new ResourceInfo() {
            @Override
            public Method getResourceMethod() {
                return method;
            }

            @Override
            public Class<?> getResourceClass() {
                return SampleResource.class;
            }
        };
    }

    private static List<String> resolve(String methodName, AuthenticationConfig config) throws Exception {
        var info = info(methodName);
        return UnannotatedWritePermissionPolicy.apply(RequiredPermissionsResolver.getRequiredPermissions(info), info,
                config);
    }

    private static AuthenticationConfig config(String permission, String exemptions) {
        var config = new AuthenticationConfig();
        config.setUnannotatedWritePermission(permission);
        config.setUnannotatedWriteExemptions(exemptions);
        return config;
    }

    @Test
    void notConfiguredKeepsUpstreamBehaviour() throws Exception {
        assertThat(resolve("create", config(null, null))).isEmpty();
        assertThat(resolve("create", config("", null))).isEmpty();
        assertThat(resolve("annotated", config(null, null))).containsExactly("project_create");
    }

    @Test
    void unannotatedWritesGetTheFallbackPermission() throws Exception {
        var config = config("workspace_write", " SampleResource#exempted , Other#x");
        assertThat(resolve("create", config)).containsExactly("workspace_write");
        assertThat(resolve("annotated", config)).containsExactly("project_create");
        assertThat(resolve("read", config)).isEmpty();
        assertThat(resolve("exempted", config)).isEmpty();
    }
}
