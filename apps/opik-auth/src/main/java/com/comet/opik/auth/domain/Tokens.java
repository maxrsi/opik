package com.comet.opik.auth.domain;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

/** Random token generation, hashing and AES-GCM helpers. */
public final class Tokens {

    public static final String SESSION_PREFIX = "ops_";
    public static final String API_KEY_PREFIX = "opk_";
    private static final String BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final String PASSWORD_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    private Tokens() {
    }

    /** {@code ops_} + base64url(32 random bytes). */
    public static String newSessionToken() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return SESSION_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /**
     * {@code opk_<8 char prefix>_<40 char base62>}. Never contains {@code *}: the Python SDK treats {@code *} as the
     * delimiter of base64 encoded key attributes.
     */
    public static ApiKeyMaterial newApiKey() {
        String prefix = randomString(BASE62, 8);
        String secret = randomString(BASE62, 40);
        return new ApiKeyMaterial(prefix, API_KEY_PREFIX + prefix + "_" + secret);
    }

    /** Extracts the lookup prefix from {@code opk_<prefix>_<secret>}, or null if the format does not match. */
    public static String apiKeyPrefix(String key) {
        if (key == null || !key.startsWith(API_KEY_PREFIX) || key.length() != API_KEY_PREFIX.length() + 8 + 1 + 40
                || key.charAt(API_KEY_PREFIX.length() + 8) != '_') {
            return null;
        }
        return key.substring(API_KEY_PREFIX.length(), API_KEY_PREFIX.length() + 8);
    }

    public static String randomPassword(int len) {
        return randomString(PASSWORD_CHARS, len);
    }

    public static String randomString(String alphabet, int len) {
        var sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
        }
        return sb.toString();
    }

    public static String sha256Hex(String value) {
        return HexFormat.of().formatHex(sha256(value.getBytes(StandardCharsets.UTF_8)));
    }

    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    /** Time-ordered UUID (v7). */
    public static String uuidV7() {
        long ms = System.currentTimeMillis();
        long randA = RANDOM.nextInt(1 << 12);
        long msb = (ms << 16) | (0x7L << 12) | randA;
        long lsb = (RANDOM.nextLong() & 0x3FFFFFFFFFFFFFFFL) | 0x8000000000000000L;
        return new UUID(msb, lsb).toString();
    }

    public static byte[] encrypt(String secret, String plaintext) {
        try {
            byte[] iv = new byte[12];
            RANDOM.nextBytes(iv);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sha256(secret.getBytes(StandardCharsets.UTF_8)), "AES"),
                    new GCMParameterSpec(128, iv));
            byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return ByteBuffer.allocate(iv.length + ct.length).put(iv).put(ct).array();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
    }

    public static String decrypt(String secret, byte[] blob) {
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sha256(secret.getBytes(StandardCharsets.UTF_8)), "AES"),
                    new GCMParameterSpec(128, blob, 0, 12));
            return new String(c.doFinal(blob, 12, blob.length - 12), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-GCM decryption failed", e);
        }
    }

    private static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public record ApiKeyMaterial(String prefix, String key) {
    }
}
