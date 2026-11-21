package com.example.auth.session;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

/**
 * Sessions and their refresh tokens in Redis. Owns every key under session:*, refresh:* and refresh-used:*.
 *
 * <pre>
 * session:&lt;id&gt;             → userId     expires at the session's maximum age; exists while the session is alive
 * refresh:&lt;sha256&gt;         → session id expires after refreshTtl, never later than its session
 * refresh-used:&lt;sha256&gt;    → session id a used token, kept for refreshTtl so a replay can be caught
 * </pre>
 *
 * Only a SHA-256 hash of each token is stored, so a Redis leak doesn't leak usable tokens.
 */
@Component
class RefreshTokenStore {

    static final String SESSION_PREFIX = "session:";
    static final String KEY_PREFIX = "refresh:";
    static final String USED_PREFIX = "refresh-used:";

    private static final RedisScript<List<String>> CONSUME = loadScript();

    private final StringRedisTemplate redis;
    private final SessionProperties props;
    private final SecureRandom random = new SecureRandom();

    /** A live session that a refresh token belonged to. */
    record Session(String id, UUID userId) {
    }

    RefreshTokenStore(StringRedisTemplate redis, SessionProperties props) {
        this.redis = redis;
        this.props = props;
    }

    /** Starts a session for the user and returns its first refresh token. */
    String startSession(UUID userId) {
        String sessionId = UUID.randomUUID().toString();
        redis.opsForValue().set(SESSION_PREFIX + sessionId, userId.toString(), props.maxSessionAge());
        return issue(sessionId).orElseThrow();
    }

    /**
     * Uses up the token in one atomic Redis script, so two requests racing with the same token can't both succeed.
     * Empty if the token is unknown, expired or already used, or its session has ended.
     * Presenting an already-used token ends its whole session.
     */
    Optional<Session> consume(String token) {
        String hash = sha256Hex(token);
        List<String> result = redis.execute(CONSUME, List.of(KEY_PREFIX + hash, USED_PREFIX + hash),
                String.valueOf(props.refreshTtl().toMillis()));
        if (result == null || result.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new Session(result.get(0), UUID.fromString(result.get(1))));
    }

    /** A new refresh token for the session. Empty if the session has ended. Never outlives the session. */
    Optional<String> issue(String sessionId) {
        Long sessionMillisLeft = redis.getExpire(SESSION_PREFIX + sessionId, TimeUnit.MILLISECONDS);
        if (sessionMillisLeft == null || sessionMillisLeft <= 0) {
            return Optional.empty();
        }
        Duration ttl = Duration.ofMillis(Math.min(sessionMillisLeft, props.refreshTtl().toMillis()));
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        redis.opsForValue().set(key(token), sessionId, ttl);
        return Optional.of(token);
    }

    /** Logout: ends the token's session. Safe to repeat, and a no-op for unknown tokens. */
    void endSession(String token) {
        String sessionId = redis.opsForValue().getAndDelete(key(token));
        if (sessionId != null) {
            redis.delete(SESSION_PREFIX + sessionId);
        }
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

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static RedisScript<List<String>> loadScript() {
        DefaultRedisScript script = new DefaultRedisScript();
        script.setLocation(new ClassPathResource("session/consume_refresh_token.lua"));
        script.setResultType(List.class);
        return script;
    }
}
