package com.example.auth.session;

import com.example.auth.identity.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.SecretKey;

/** Signs and verifies access tokens (HS256). Package-private: only SessionService uses it. */
class JwtCodec {

    private static final String ROLE_CLAIM = "role";

    private final SecretKey key;
    private final Duration ttl;
    private final Clock clock;

    JwtCodec(SecretKey key, Duration ttl, Clock clock) {
        this.key = key;
        this.ttl = ttl;
        this.clock = clock;
    }

    Duration ttl() {
        return ttl;
    }

    String encode(AccessClaims claims) {
        Instant now = clock.instant();
        return Jwts.builder()
                .subject(claims.userId().toString())
                .claim(ROLE_CLAIM, claims.role().name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(ttl)))
                .signWith(key)
                .compact();
    }

    /** Empty for any token that is malformed, expired, unsigned or signed with another key. */
    Optional<AccessClaims> decode(String token) {
        try {
            // verifyWith(SecretKey) only accepts HMAC signatures, so "alg: none" tokens are rejected.
            Claims payload = Jwts.parser()
                    .verifyWith(key)
                    .clock(() -> Date.from(clock.instant()))
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return Optional.of(new AccessClaims(
                    UUID.fromString(payload.getSubject()),
                    Role.valueOf(payload.get(ROLE_CLAIM, String.class))));
        } catch (JwtException | IllegalArgumentException | NullPointerException e) {
            return Optional.empty();
        }
    }
}
