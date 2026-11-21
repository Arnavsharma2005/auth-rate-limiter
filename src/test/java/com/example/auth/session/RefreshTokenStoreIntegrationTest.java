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
    void createStoresOnlyTheHashWithA7DayExpiry() {
        String token = store.create(userId);

        assertThat(token).matches("[A-Za-z0-9_-]{43}"); // 32 random bytes, URL-safe Base64
        assertThat(redis.opsForValue().get(RefreshTokenStore.key(token))).isEqualTo(userId.toString());
        assertThat(redis.hasKey("refresh:" + token)).isFalse();
        long ttl = redis.getExpire(RefreshTokenStore.key(token));
        assertThat(ttl).isBetween(Duration.ofDays(7).minusMinutes(1).toSeconds(), Duration.ofDays(7).toSeconds());
    }

    @Test
    void tokensAreUnique() {
        assertThat(store.create(userId)).isNotEqualTo(store.create(userId));
    }

    @Test
    void consumeWorksExactlyOnce() {
        String token = store.create(userId);

        assertThat(store.consume(token)).contains(userId);
        assertThat(store.consume(token)).isEmpty();
    }

    @Test
    void concurrentConsumeOfOneTokenSucceedsOnlyOnce() throws Exception {
        String token = store.create(userId);
        ExecutorService pool = Executors.newFixedThreadPool(10);
        try {
            List<Callable<Optional<UUID>>> calls = new ArrayList<>();
            for (int i = 0; i < 10; i++) {
                calls.add(() -> store.consume(token));
            }
            long winners = 0;
            for (Future<Optional<UUID>> f : pool.invokeAll(calls)) {
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
    void deleteRevokesAndIsSafeToRepeat() {
        String token = store.create(userId);

        store.delete(token);
        store.delete(token);
        store.delete("never-existed");

        assertThat(store.consume(token)).isEmpty();
    }
}
