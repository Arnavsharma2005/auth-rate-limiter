package com.example.auth.ratelimit;

/** Decides whether one more action is allowed for a key (for example "login:203.0.113.7"). */
public interface RateLimiter {

    /**
     * @param allowed           true if the action may go ahead
     * @param retryAfterSeconds when denied, how long until the next attempt is allowed (at least 1)
     */
    record Decision(boolean allowed, long retryAfterSeconds) {
    }

    Decision tryAcquire(String key);
}
