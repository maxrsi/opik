package com.comet.opik.auth;

import com.comet.opik.auth.audit.AuditLogger;
import com.comet.opik.auth.audit.AuditQueryService;
import com.comet.opik.auth.bootstrap.BootstrapAdmin;
import com.comet.opik.auth.bootstrap.ResetAdminPasswordCommand;
import com.comet.opik.auth.config.OpikAuthConfiguration;
import com.comet.opik.auth.db.ApiKeyDao;
import com.comet.opik.auth.db.RbacDao;
import com.comet.opik.auth.db.SessionDao;
import com.comet.opik.auth.db.UserDao;
import com.comet.opik.auth.domain.AccountService;
import com.comet.opik.auth.domain.AuthCore;
import com.comet.opik.auth.domain.PasswordHasher;
import com.comet.opik.auth.resources.AdminResource;
import com.comet.opik.auth.resources.AuthApiResource;
import com.comet.opik.auth.resources.ProtocolResource;
import com.comet.opik.auth.web.CsrfFilter;
import com.comet.opik.auth.web.SessionPrincipals;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.db.DataSourceFactory;
import io.dropwizard.jdbi3.JdbiFactory;
import io.dropwizard.migrations.MigrationsBundle;
import liquibase.Liquibase;
import liquibase.database.DatabaseFactory;
import liquibase.database.jvm.JdbcConnection;
import liquibase.resource.ClassLoaderResourceAccessor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jdbi.v3.core.Jdbi;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.TimeUnit;

/**
 * opik-auth: local username/password login, workspace roles, API keys and the "react-service" auth protocol that
 * opik-backend's {@code RemoteAuthService} calls when {@code authentication.enabled=true}.
 */
@Slf4j
public class OpikAuthApplication extends Application<OpikAuthConfiguration> {

    public static final String CHANGELOG = "liquibase/db-auth/changelog.xml";

    public static void main(String[] args) throws Exception {
        new OpikAuthApplication().run(args);
    }

    @Override
    public String getName() {
        return "opik-auth";
    }

    @Override
    public void initialize(Bootstrap<OpikAuthConfiguration> bootstrap) {
        bootstrap.setConfigurationSourceProvider(new SubstitutingSourceProvider(
                bootstrap.getConfigurationSourceProvider(), new EnvironmentVariableSubstitutor(false)));
        bootstrap.addBundle(new MigrationsBundle<>() {
            @Override
            public DataSourceFactory getDataSourceFactory(OpikAuthConfiguration configuration) {
                return configuration.getDatabase();
            }

            @Override
            public String getMigrationsFileName() {
                return CHANGELOG;
            }
        });
        bootstrap.addCommand(new ResetAdminPasswordCommand());
    }

    @Override
    public void run(OpikAuthConfiguration config, Environment environment) throws Exception {
        var settings = config.getAuth();
        if (StringUtils.length(settings.getSecret()) < 32) {
            throw new IllegalStateException("auth.secret (OPIK_AUTH_SECRET) must be at least 32 characters");
        }
        environment.getObjectMapper().disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        if (config.isAutoMigrate()) {
            migrate(config, environment);
        }

        Jdbi jdbi = new JdbiFactory().build(environment, config.getDatabase(), "mysql");
        Clock clock = Clock.systemUTC();
        var hasher = new PasswordHasher();
        var audit = new AuditLogger(config.getClickhouse(), environment.getObjectMapper());
        environment.lifecycle().manage(audit);

        var rbacDao = jdbi.onDemand(RbacDao.class);
        var authCore = new AuthCore(jdbi.onDemand(UserDao.class), rbacDao, jdbi.onDemand(SessionDao.class),
                jdbi.onDemand(ApiKeyDao.class), settings, clock);
        var accounts = new AccountService(jdbi, hasher, authCore, audit, settings, clock);
        var principals = new SessionPrincipals(authCore, settings);

        BootstrapAdmin.ensure(jdbi, hasher, settings, audit, clock);

        var jersey = environment.jersey();
        jersey.register(new CsrfFilter(settings.getPublicOrigins()));
        jersey.register(new ProtocolResource(authCore, audit, settings));
        jersey.register(new AuthApiResource(accounts, authCore, principals, settings));
        jersey.register(new AdminResource(accounts, authCore, rbacDao, principals,
                new AuditQueryService(config.getClickhouse(), environment.getObjectMapper())));

        // housekeeping: purge sessions that expired / were revoked more than a day ago
        var sessions = jdbi.onDemand(SessionDao.class);
        var housekeeping = environment.lifecycle().scheduledExecutorService("session-purge").threads(1).build();
        housekeeping.scheduleWithFixedDelay(() -> {
            try {
                int purged = sessions.purge(Instant.now().minus(1, ChronoUnit.DAYS));
                if (purged > 0) {
                    log.info("Purged {} expired sessions", purged);
                }
            } catch (RuntimeException e) {
                log.warn("Session purge failed", e);
            }
        }, 1, 60, TimeUnit.MINUTES);
    }

    private static void migrate(OpikAuthConfiguration config, Environment environment) throws Exception {
        var dataSource = config.getDatabase().build(environment.metrics(), "migrations");
        try (var connection = dataSource.getConnection()) {
            var database = DatabaseFactory.getInstance()
                    .findCorrectDatabaseImplementation(new JdbcConnection(connection));
            try (var liquibase = new Liquibase(CHANGELOG, new ClassLoaderResourceAccessor(), database)) {
                liquibase.update("");
            }
        }
    }
}
