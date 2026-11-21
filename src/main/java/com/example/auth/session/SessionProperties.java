package com.example.auth.session;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Settings under auth.session.* in application.yml.
 *
 * @param jwtSecret  HMAC key for signing access tokens, at least 32 bytes. Blank = random key per startup (dev only).
 * @param accessTtl  how long an access token is valid
 * @param refreshTtl how long a refresh token is valid
 */
@ConfigurationProperties("auth.session")
record SessionProperties(
        String jwtSecret,
        @DefaultValue("15m") Duration accessTtl,
        @DefaultValue("7d") Duration refreshTtl) {
}
