package com.comet.opik.auth.domain;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Argon2id password hashing, stored as a PHC string: {@code $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>}.
 * Pure Java (BouncyCastle), no native library needed.
 */
public final class PasswordHasher {

    public static final int DEFAULT_MEMORY_KIB = 19456;
    public static final int DEFAULT_ITERATIONS = 2;
    public static final int DEFAULT_PARALLELISM = 1;
    private static final int SALT_LEN = 16;
    private static final int HASH_LEN = 32;
    private static final Base64.Encoder B64 = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getDecoder();
    private static final SecureRandom RANDOM = new SecureRandom();

    private final int memoryKib;
    private final int iterations;
    private final int parallelism;
    /** Hash of a random password, used to equalise timing when the user does not exist. */
    private final String dummyHash;

    public PasswordHasher() {
        this(DEFAULT_MEMORY_KIB, DEFAULT_ITERATIONS, DEFAULT_PARALLELISM);
    }

    public PasswordHasher(int memoryKib, int iterations, int parallelism) {
        this.memoryKib = memoryKib;
        this.iterations = iterations;
        this.parallelism = parallelism;
        this.dummyHash = hash(Tokens.randomPassword(24));
    }

    public String hash(String password) {
        byte[] salt = new byte[SALT_LEN];
        RANDOM.nextBytes(salt);
        byte[] out = derive(password, salt, memoryKib, iterations, parallelism, HASH_LEN);
        return "$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s".formatted(memoryKib, iterations, parallelism,
                B64.encodeToString(salt), B64.encodeToString(out));
    }

    public boolean verify(String password, String phc) {
        if (password == null || phc == null) {
            return false;
        }
        try {
            String[] parts = phc.split("\\$");
            // ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
            if (parts.length != 6 || !"argon2id".equals(parts[1]) || !"v=19".equals(parts[2])) {
                return false;
            }
            int m = 0, t = 0, p = 0;
            for (String kv : parts[3].split(",")) {
                String[] pair = kv.split("=");
                switch (pair[0]) {
                    case "m" -> m = Integer.parseInt(pair[1]);
                    case "t" -> t = Integer.parseInt(pair[1]);
                    case "p" -> p = Integer.parseInt(pair[1]);
                    default -> {
                        return false;
                    }
                }
            }
            byte[] salt = B64D.decode(parts[4]);
            byte[] expected = B64D.decode(parts[5]);
            byte[] actual = derive(password, salt, m, t, p, expected.length);
            return MessageDigest.isEqual(expected, actual);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** True when the stored hash uses different (outdated) parameters and should be re-hashed after login. */
    public boolean needsRehash(String phc) {
        return phc == null || !phc.startsWith("$argon2id$v=19$m=%d,t=%d,p=%d$".formatted(memoryKib, iterations,
                parallelism));
    }

    /** Burns the same CPU/memory as a real verification; always false. */
    public boolean verifyDummy(String password) {
        verify(password == null ? "" : password, dummyHash);
        return false;
    }

    private static byte[] derive(String password, byte[] salt, int m, int t, int p, int len) {
        var params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(m)
                .withIterations(t)
                .withParallelism(p)
                .withSalt(salt)
                .build();
        var gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[len];
        gen.generateBytes(password.getBytes(StandardCharsets.UTF_8), out);
        return out;
    }
}
