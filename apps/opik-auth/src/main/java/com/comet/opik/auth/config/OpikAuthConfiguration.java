package com.comet.opik.auth.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.core.Configuration;
import io.dropwizard.db.DataSourceFactory;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OpikAuthConfiguration extends Configuration {

    @Valid @NotNull @JsonProperty
    private DataSourceFactory database = new DataSourceFactory();

    /** Run Liquibase migrations on startup (in addition to the explicit {@code db migrate} command). */
    @JsonProperty
    private boolean autoMigrate = true;

    @Valid @NotNull @JsonProperty
    private AuthSettings auth = new AuthSettings();

    @Valid @NotNull @JsonProperty
    private ClickHouseSettings clickhouse = new ClickHouseSettings();
}
