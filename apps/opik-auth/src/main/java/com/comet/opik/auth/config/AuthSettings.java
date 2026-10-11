package com.comet.opik.auth.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.util.Duration;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthSettings {

    /** Secret used to derive the AES-GCM key that protects session-derived UI API keys. 32+ bytes recommended. */
    @NotNull @JsonProperty
    private String secret = "";

    /** Name of the session cookie. MUST stay {@code sessionToken}: opik-backend reads exactly this cookie. */
    @NotNull @JsonProperty
    private String cookieName = "sessionToken";

    @JsonProperty
    private boolean cookieSecure = false;

    /**
     * Allowed browser origins for state-changing /auth/api calls (CSRF defence), comma separated.
     * Empty disables the Origin check.
     */
    @NotNull @JsonProperty
    private String publicOrigins = "";

    @NotNull @JsonProperty
    private Duration sessionIdleTimeout = Duration.hours(12);

    @NotNull @JsonProperty
    private Duration sessionAbsoluteTimeout = Duration.days(7);

    @NotNull @JsonProperty
    private String bootstrapAdminUsername = "admin";

    /** Empty: a random password is generated and printed once to the log. */
    @NotNull @JsonProperty
    private String bootstrapAdminPassword = "";

    @Min(1) @JsonProperty
    private int loginMaxFailures = 5;

    @NotNull @JsonProperty
    private Duration loginLockout = Duration.minutes(15);

    @Min(8) @JsonProperty
    private int passwordMinLength = 12;

    /** Default workspace name; must match opik-backend's ProjectService.DEFAULT_WORKSPACE_NAME. */
    @NotNull @JsonProperty
    private String defaultWorkspaceName = "default";
}
