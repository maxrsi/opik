package com.comet.opik.auth.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ClickHouseSettings {

    /** When false, auth audit events are only logged and the audit query API answers 503. */
    @JsonProperty
    private boolean enabled = false;

    /** HTTP interface base URL, e.g. http://clickhouse:8123 */
    @NotNull @JsonProperty
    private String url = "http://clickhouse:8123";

    @NotNull @JsonProperty
    private String database = "opik";

    @NotNull @JsonProperty
    private String user = "opik";

    @NotNull @JsonProperty
    private String password = "opik";
}
