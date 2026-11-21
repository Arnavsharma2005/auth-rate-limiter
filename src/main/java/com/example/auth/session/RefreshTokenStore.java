package com.example.auth.session;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/**
 * Refresh tokens in Redis. Owns every key under refresh:*.
 * Only a SHA-256 hash of each token is stored, so a Redis leak doesn't leak usable tokens.
 */
@Component
class RefreshTokenStore {

    static final String KEY_PREFIX = "refresh:";

    private final StringRedisTemplate redis;
    private final SessionProperties props;
    private final SecureRandom random = new SecureRandom();

    RefreshTokenStore(StringRedisTemplate redis, SessionProperties props) {
        this.redis = redis;
        this.props = props;
    }

    /** Creates a token for the user and returns the raw value. Only its hash is stored. */
    String create(UUID userId) {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        redis.opsForValue().set(key(token), userId.toString(), props.refreshTtl());
        return token;
    }

    /**
     * Returns the token's user and deletes the token in one atomic Redis call (GETDEL),
     * so two requests racing with the same token can't both succeed. Empty if unknown or expired.
     */
    Optional<UUID> consume(String token) {
        return Optional.ofNullable(redis.opsForValue().getAndDelete(key(token))).map(UUID::fromString);
    }

    void delete(String token) {
        redis.delete(key(token));
    }

    static String key(String token) {
        return KEY_PREFIX + sha256Hex(token);
    }

    private static String sha256Hex(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is always available", e);
        }
    }
}
