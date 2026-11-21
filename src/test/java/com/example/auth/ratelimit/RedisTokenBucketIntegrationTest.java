package com.example.auth.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.IntegrationTest;
import com.example.auth.ratelimit.RateLimiter.Decision;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;

/** Integration test: the real Lua script running in a real Redis container. */
@IntegrationTest
class RedisTokenBucketIntegrationTest {

    /** A clock the test can move forward. */
    static class TestClock extends Clock {
        private Instant now = Instant.parse("2026-01-01T12:00:00Z");

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override public Instant instant() { return now; }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
    }

    @Autowired StringRedisTemplate redis;

    private final TestClock clock = new TestClock();
    private RedisTokenBucket bucket;
    private String key;

    @BeforeEach
    void setUp() {
        // 5 tokens, refilled at 5 per minute = 1 token every 12 seconds
        bucket = new RedisTokenBucket(redis, 5, Duration.ofMinutes(1), clock);
        key = "test:" + UUID.randomUUID();
    }

    @Test
    void allowsCapacityThenDeniesWithRetryAfter() {
        for (int i = 1; i <= 5; i++) {
            assertThat(bucket.tryAcquire(key).allowed()).as("attempt " + i).isTrue();
        }
        Decision sixth = bucket.tryAcquire(key);
        assertThat(sixth.allowed()).isFalse();
        assertThat(sixth.retryAfterSeconds()).isEqualTo(12);
    }

    @Test
    void refillsOneTokenEvery12Seconds() {
        drain();
        clock.advance(Duration.ofSeconds(11));
        assertThat(bucket.tryAcquire(key).allowed()).isFalse();
        clock.advance(Duration.ofSeconds(1));
        assertThat(bucket.tryAcquire(key).allowed()).isTrue();
        assertThat(bucket.tryAcquire(key).allowed()).isFalse();
    }

    @Test
    void neverHoldsMoreThanCapacity() {
        drain();
        clock.advance(Duration.ofHours(1));
        drain(); // 5 again, not 300
        assertThat(bucket.tryAcquire(key).allowed()).isFalse();
    }

    @Test
    void keysAreIndependent() {
        drain();
        assertThat(bucket.tryAcquire(key + ":other").allowed()).isTrue();
    }

    @Test
    void bucketKeyExpiresInRedis() {
        bucket.tryAcquire(key);
        assertThat(redis.getExpire("rl:" + key)).isPositive();
    }

    @Test
    void concurrentRequestsCannotOverspend() throws Exception {
        // 20 requests at the same moment: the Lua script is atomic, so exactly 5 may pass
        ExecutorService pool = Executors.newFixedThreadPool(20);
        try {
            List<Callable<Boolean>> calls = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                calls.add(() -> bucket.tryAcquire(key).allowed());
            }
            long allowed = 0;
            for (Future<Boolean> f : pool.invokeAll(calls)) {
                if (f.get()) {
                    allowed++;
                }
            }
            assertThat(allowed).isEqualTo(5);
        } finally {
            pool.shutdownNow();
        }
    }

    private void drain() {
        for (int i = 0; i < 5; i++) {
            assertThat(bucket.tryAcquire(key).allowed()).isTrue();
        }
    }
}
