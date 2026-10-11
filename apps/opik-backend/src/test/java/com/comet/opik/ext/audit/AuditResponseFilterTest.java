package com.comet.opik.ext.audit;

import com.comet.opik.infrastructure.OpikConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import jakarta.ws.rs.container.ContainerResponseContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.File;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuditResponseFilterTest {

    private static AuditResponseFilter filterWithShippedExcludes() throws Exception {
        var yaml = new ObjectMapper(new YAMLFactory()).readTree(new File("config.yml"));
        List<String> excludes = new ArrayList<>();
        yaml.path("audit").path("excludeRoutes").forEach(node -> excludes.add(node.asText()));
        assertThat(excludes).isNotEmpty();
        var configuration = new OpikConfiguration();
        configuration.getAudit().setExcludeRoutes(excludes);
        return new AuditResponseFilter(mock(AuditLogWriter.class), configuration);
    }

    @ParameterizedTest
    @CsvSource({
            "POST /v1/private/traces, true",
            "POST /v1/private/traces/batch, true",
            "PATCH /v1/private/spans/0190babc-62a0-71d2-832a-0feffa4676eb, true",
            "POST /v1/private/traces/search, true",
            "POST /v1/private/traces/threads/retrieve, true",
            "POST /v1/private/otel/v1/traces, true",
            "PUT /v1/private/traces/feedback-scores, true",
            "POST /v1/private/workspaces/costs/summaries, true",
            "DELETE /v1/private/traces/0190babc-62a0-71d2-832a-0feffa4676eb, false",
            "POST /v1/private/traces/delete, false",
            "POST /v1/private/projects, false",
            "PATCH /v1/private/projects/0190babc-62a0-71d2-832a-0feffa4676eb, false",
            "POST /v1/private/datasets, false",
            "PUT /v1/private/traces/0190babc-62a0-71d2-832a-0feffa4676eb/feedback-scores, false",
            "POST /v1/private/experiments/delete, false"
    })
    void shippedExclusions(String methodAndPath, boolean excluded) throws Exception {
        assertThat(filterWithShippedExcludes().isExcluded(methodAndPath)).isEqualTo(excluded);
    }

    @Test
    void helpers() {
        assertThat(AuditResponseFilter.resourceType("ProjectsResource")).isEqualTo("projects");
        assertThat(AuditResponseFilter.resourceType("FeedbackDefinitionResource")).isEqualTo("feedbackDefinition");
        assertThat(AuditResponseFilter.isAuditedPath("/v1/private/projects")).isTrue();
        assertThat(AuditResponseFilter.isAuditedPath("/v1/internal/usage")).isFalse();

        var response = mock(ContainerResponseContext.class);
        var params = new LinkedHashMap<String, String>();
        params.put("id", "abc");
        assertThat(AuditResponseFilter.resourceId(params, response)).isEqualTo("abc");
        when(response.getLocation()).thenReturn(URI.create("http://x/v1/private/projects/new-id"));
        assertThat(AuditResponseFilter.resourceId(new LinkedHashMap<>(), response)).isEqualTo("new-id");
    }
}
