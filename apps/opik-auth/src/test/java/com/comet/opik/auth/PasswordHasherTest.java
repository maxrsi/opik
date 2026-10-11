package com.comet.opik.auth;

import com.comet.opik.auth.domain.PasswordHasher;
import com.comet.opik.auth.domain.Tokens;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordHasherTest {

    private final PasswordHasher hasher = new PasswordHasher();

    @Test
    void hashesAsPhcAndVerifies() {
        String hash = hasher.hash("correct horse battery");
        assertThat(hash).startsWith("$argon2id$v=19$m=19456,t=2,p=1$");
        assertThat(hasher.verify("correct horse battery", hash)).isTrue();
        assertThat(hasher.verify("wrong password!!", hash)).isFalse();
        assertThat(hasher.needsRehash(hash)).isFalse();
    }

    @Test
    void saltsDiffer() {
        assertThat(hasher.hash("same password 1")).isNotEqualTo(hasher.hash("same password 1"));
    }

    @Test
    void detectsOutdatedParameters() {
        var weak = new PasswordHasher(8192, 1, 1);
        String old = weak.hash("legacy password");
        assertThat(hasher.verify("legacy password", old)).isTrue();
        assertThat(hasher.needsRehash(old)).isTrue();
    }

    @Test
    void rejectsGarbage() {
        assertThat(hasher.verify("x", "not-a-phc")).isFalse();
        assertThat(hasher.verify("x", "$argon2i$v=19$m=1,t=1,p=1$AAAA$AAAA")).isFalse();
        assertThat(hasher.verify(null, null)).isFalse();
        assertThat(hasher.verifyDummy("anything")).isFalse();
    }

    @Test
    void tokenFormats() {
        var key = Tokens.newApiKey();
        assertThat(key.key()).matches("opk_[0-9A-Za-z]{8}_[0-9A-Za-z]{40}").doesNotContain("*");
        assertThat(Tokens.apiKeyPrefix(key.key())).isEqualTo(key.prefix());
        assertThat(Tokens.apiKeyPrefix("opk_short")).isNull();
        assertThat(Tokens.newSessionToken()).startsWith("ops_").hasSizeGreaterThan(40);
        assertThat(Tokens.uuidV7()).matches("[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");
        byte[] enc = Tokens.encrypt("0123456789abcdef0123456789abcdef", "secret value");
        assertThat(Tokens.decrypt("0123456789abcdef0123456789abcdef", enc)).isEqualTo("secret value");
    }
}
