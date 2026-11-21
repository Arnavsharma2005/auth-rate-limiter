package com.example.auth.session;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.IntegrationTest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;

/** Integration test: RefreshTokenStore against a real Redis container. */
@IntegrationTest
class RefreshTokenStoreIntegrationTest {

    @Autowired RefreshTokenStore store;
    @Autowired StringRedisTemplate redis;

    private final UUID userId = UUID.randomUUID();

    @Test
    void startSessionStoresOnlyTheHashWithA7DayExpiry() {
        String token = store.startSession(userId);

        assertThat(token).matches("[A-Za-z0-9_-]{43}"); // 32 random bytes, URL-safe Base64
        String sessionId = redis.opsForValue().get(RefreshTokenStore.key(token));
        assertThat(redis.opsForValue().get("session:" + sessionId)).isEqualTo(userId.toString());
        assertThat(redis.hasKey("refresh:" + token)).isFalse();
        long ttl = redis.getExpire(RefreshTokenStore.key(token));
        assertThat(ttl).isBetween(Duration.ofDays(7).minusMinutes(1).toSeconds(), Duration.ofDays(7).toSeconds());
    }

    @Test
    void tokensAreUnique() {
        assertThat(store.startSession(userId)).isNotEqualTo(store.startSession(userId));
    }

    @Test
    void consumeWorksExactlyOnce() {
        String token = store.startSession(userId);

        assertThat(store.consume(token)).map(RefreshTokenStore.Session::userId).contains(userId);
        assertThat(store.consume(token)).isEmpty();
    }

    @Test
    void concurrentConsumeOfOneTokenSucceedsOnlyOnce() throws Exception {
        String token = store.startSession(userId);
        ExecutorService pool = Executors.newFixedThreadPool(10);
        try {
            List<Callable<Optional<RefreshTokenStore.Session>>> calls = new ArrayList<>();
            for (int i = 0; i < 10; i++) {
                calls.add(() -> store.consume(token));
            }
            long winners = 0;
            for (Future<Optional<RefreshTokenStore.Session>> f : pool.invokeAll(calls)) {
                if (f.get().isPresent()) {
                    winners++;
                }
            }
            assertThat(winners).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void replayingAUsedTokenEndsTheSession() {
        String first = store.startSession(userId);
        RefreshTokenStore.Session session = store.consume(first).orElseThrow();
        String second = store.issue(session.id()).orElseThrow();

        assertThat(store.consume(first)).isEmpty();
        assertThat(store.consume(second)).isEmpty();
        assertThat(store.issue(session.id())).isEmpty();
    }

    @Test
    void tokensNeverOutliveTheirSession() {
        String first = store.startSession(userId);
        RefreshTokenStore.Session session = store.consume(first).orElseThrow();
        redis.expire("session:" + session.id(), Duration.ofSeconds(30));

        String next = store.issue(session.id()).orElseThrow();

        assertThat(redis.getExpire(RefreshTokenStore.key(next), TimeUnit.MILLISECONDS)).isBetween(1L, 30_000L);
    }

    @Test
    void anEndedSessionCannotBeRefreshed() {
        String token = store.startSession(userId);
        String sessionId = redis.opsForValue().get(RefreshTokenStore.key(token));
        redis.delete("session:" + sessionId); // what expiry at maxSessionAge does

        assertThat(store.consume(token)).isEmpty();
        assertThat(store.issue(sessionId)).isEmpty();
    }

    @Test
    void endSessionRevokesAndIsSafeToRepeat() {
        String token = store.startSession(userId);
        String sessionId = redis.opsForValue().get(RefreshTokenStore.key(token));

        store.endSession(token);
        store.endSession(token);
        store.endSession("never-existed");

        assertThat(store.consume(token)).isEmpty();
        assertThat(redis.hasKey("session:" + sessionId)).isFalse();
    }
}
