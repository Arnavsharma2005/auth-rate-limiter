package com.example.auth.ratelimit;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;

/**
 * Token bucket stored in Redis. Owns every key under rl:*.
 * The read-refill-take logic runs inside one Lua script (token_bucket.lua), which Redis executes atomically.
 */
class RedisTokenBucket implements RateLimiter {

    private static final String KEY_PREFIX = "rl:";

    private static final RedisScript<List<Long>> SCRIPT = loadScript();

    private final StringRedisTemplate redis;
    private final int capacity;
    private final double tokensPerMilli;
    private final long keyTtlMillis;
    private final Clock clock;

    /**
     * @param capacity     most tokens a bucket can hold (the burst size)
     * @param refillPeriod time to refill an empty bucket completely
     */
    RedisTokenBucket(StringRedisTemplate redis, int capacity, Duration refillPeriod, Clock clock) {
        this.redis = redis;
        this.capacity = capacity;
        this.tokensPerMilli = (double) capacity / refillPeriod.toMillis();
        // Once a bucket would be full again, its state is no longer needed
        this.keyTtlMillis = refillPeriod.toMillis() * 2;
        this.clock = clock;
    }

    @Override
    public Decision tryAcquire(String key) {
        List<Long> result = redis.execute(SCRIPT, List.of(KEY_PREFIX + key),
                String.valueOf(capacity),
                String.valueOf(tokensPerMilli),
                String.valueOf(clock.millis()),
                String.valueOf(keyTtlMillis));
        boolean allowed = result.get(0) == 1L;
        long retryAfterSeconds = allowed ? 0 : Math.max(1, ceilDiv(result.get(1), 1000));
        return new Decision(allowed, retryAfterSeconds);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private static RedisScript<List<Long>> loadScript() {
        // Redis returns the Lua table as a List of Longs
        DefaultRedisScript script = new DefaultRedisScript();
        script.setLocation(new ClassPathResource("ratelimit/token_bucket.lua"));
        script.setResultType(List.class);
        return script;
    }

    private static long ceilDiv(long a, long b) {
        return (a + b - 1) / b;
    }
}
