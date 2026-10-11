package com.comet.opik.auth.bootstrap;

import com.comet.opik.auth.config.OpikAuthConfiguration;
import com.comet.opik.auth.db.ApiKeyDao;
import com.comet.opik.auth.db.SessionDao;
import com.comet.opik.auth.db.UserDao;
import com.comet.opik.auth.domain.LocalPasswordProvider;
import com.comet.opik.auth.domain.PasswordHasher;
import com.comet.opik.auth.domain.Tokens;
import io.dropwizard.core.cli.ConfiguredCommand;
import io.dropwizard.core.setup.Bootstrap;
import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.inf.Subparser;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;

import java.time.Instant;

/**
 * Recovery: {@code java -jar opik-auth.jar reset-admin-password config.yml --username admin}. Sets a new random
 * password (printed to stdout), forces a change at next login, re-enables the user and revokes all its sessions.
 */
public class ResetAdminPasswordCommand extends ConfiguredCommand<OpikAuthConfiguration> {

    public ResetAdminPasswordCommand() {
        super("reset-admin-password", "Reset a user's local password and print the new random password");
    }

    @Override
    public void configure(Subparser subparser) {
        super.configure(subparser);
        subparser.addArgument("--username").dest("username").setDefault("admin")
                .help("user whose password is reset (default: admin)");
    }

    @Override
    protected void run(Bootstrap<OpikAuthConfiguration> bootstrap, Namespace namespace,
            OpikAuthConfiguration configuration) throws Exception {
        var dataSource = configuration.getDatabase().build(bootstrap.getMetricRegistry(), "reset-admin");
        var jdbi = Jdbi.create(dataSource).installPlugin(new SqlObjectPlugin());
        String username = namespace.getString("username");
        String password = Tokens.randomPassword(20);
        var hasher = new PasswordHasher();
        jdbi.useTransaction(handle -> {
            var users = handle.attach(UserDao.class);
            var user = users.findByUsername(username)
                    .orElseThrow(() -> new IllegalArgumentException("No such user: " + username));
            Instant now = Instant.now();
            if (users.updateLocalSecret(user.id(), hasher.hash(password), now) == 0) {
                users.insertIdentity(Tokens.uuidV7(), user.id(), LocalPasswordProvider.PROVIDER,
                        LocalPasswordProvider.subject(user.username()), hasher.hash(password), now);
            }
            users.setMustChangePassword(user.id(), true);
            users.updateStatus(user.id(), "active");
            var sessions = handle.attach(SessionDao.class);
            var keys = handle.attach(ApiKeyDao.class);
            for (var s : sessions.findActiveByUser(user.id())) {
                sessions.revoke(s.idHash(), now);
            }
            keys.revokeSessionKeysOfUser(user.id(), now, "reset-admin-password");
        });
        System.out.println("New password for '" + username + "': " + password);
        System.out.println("The user must change it at next login. All sessions were revoked.");
    }
}
