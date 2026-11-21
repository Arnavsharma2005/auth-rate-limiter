package com.example.auth.ratelimit;

import java.time.Clock;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

@Configuration
class RateLimitConfig {

    /** Default: 5 login attempts, refilled at a rate of 5 per minute. */
    @Bean
    RateLimiter loginRateLimiter(
            StringRedisTemplate redis,
            @Value("${auth.rate-limit.login.capacity:5}") int capacity,
            @Value("${auth.rate-limit.login.refill-period:1m}") Duration refillPeriod) {
        return new RedisTokenBucket(redis, capacity, refillPeriod, Clock.systemUTC());
    }
}
