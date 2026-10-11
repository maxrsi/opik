package com.comet.opik.ext.audit;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.util.Duration;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;

/**
 * Fork-only audit log configuration ({@code audit:} in config.yml). Disabled by default.
 */
@Data
public class AuditConfig {

    @JsonProperty
    private boolean enabled = false;

    /** Also record requests rejected with 401/403 (action {@code http.denied}). */
    @JsonProperty
    private boolean recordDenied = true;

    /**
     * Regexes matched against {@code "<METHOD> <path>"} (path without query, e.g. {@code "POST /v1/private/traces"});
     * matching write requests are not audited (read-only POSTs and high-frequency SDK ingestion).
     */
    @NotNull @JsonProperty
    private List<String> excludeRoutes = List.of();

    @Min(100) @JsonProperty
    private int queueCapacity = 10_000;

    @Min(1) @JsonProperty
    private int batchSize = 500;

    @NotNull @JsonProperty
    private Duration flushInterval = Duration.seconds(2);
}
