package com.comet.opik.auth.domain;

import com.comet.opik.auth.db.UserDao;

import java.time.Clock;
import java.util.Locale;
import java.util.Optional;

/** Username + argon2id password stored in {@code user_identities(provider='local')}. */
public class LocalPasswordProvider implements IdentityProvider {

    public static final String PROVIDER = "local";

    private final UserDao userDao;
    private final PasswordHasher hasher;
    private final Clock clock;

    public LocalPasswordProvider(UserDao userDao, PasswordHasher hasher, Clock clock) {
        this.userDao = userDao;
        this.hasher = hasher;
        this.clock = clock;
    }

    @Override
    public String id() {
        return PROVIDER;
    }

    @Override
    public Optional<String> authenticate(String username, String password) {
        if (username == null || password == null) {
            hasher.verifyDummy(password);
            return Optional.empty();
        }
        var identity = userDao.findIdentity(PROVIDER, subject(username)).orElse(null);
        if (identity == null || identity.secretHash() == null) {
            // same cost as a real verification so response time does not reveal whether the user exists
            hasher.verifyDummy(password);
            return Optional.empty();
        }
        if (!hasher.verify(password, identity.secretHash())) {
            return Optional.empty();
        }
        if (hasher.needsRehash(identity.secretHash())) {
            userDao.updateLocalSecret(identity.userId(), hasher.hash(password), clock.instant());
        }
        userDao.touchIdentity(identity.id(), clock.instant());
        return Optional.of(identity.userId());
    }

    public static String subject(String username) {
        return username.strip().toLowerCase(Locale.ROOT);
    }
}
