package com.example.auth.session;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.identity.Role;
import io.jsonwebtoken.Jwts;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("unit")
class JwtCodecTest {

    private static final Instant T0 = Instant.parse("2026-01-01T12:00:00Z");
    private static final Duration TTL = Duration.ofMinutes(15);

    private final SecretKey key = Jwts.SIG.HS256.key().build();
    private final AccessClaims claims = new AccessClaims(UUID.randomUUID(), Role.ADMIN);

    @Test
    void decodesWhatItEncoded() {
        JwtCodec codec = codecAt(key, T0);
        assertThat(codec.decode(codec.encode(claims))).contains(claims);
    }

    @Test
    void rejectsExpiredToken() {
        String token = codecAt(key, T0).encode(claims);
        assertThat(codecAt(key, T0.plus(TTL).minusSeconds(1)).decode(token)).isPresent();
        assertThat(codecAt(key, T0.plus(TTL).plusSeconds(1)).decode(token)).isEmpty();
    }

    @Test
    void rejectsTokenSignedWithAnotherKey() {
        String token = codecAt(Jwts.SIG.HS256.key().build(), T0).encode(claims);
        assertThat(codecAt(key, T0).decode(token)).isEmpty();
    }

    @Test
    void rejectsTamperedPayload() {
        JwtCodec codec = codecAt(key, T0);
        String[] parts = codec.encode(claims).split("\\.");
        // Swap in a payload claiming a different user, keep the original signature
        String forgedPayload = codecAt(key, T0).encode(new AccessClaims(UUID.randomUUID(), Role.ADMIN)).split("\\.")[1];
        assertThat(codec.decode(parts[0] + "." + forgedPayload + "." + parts[2])).isEmpty();
    }

    @Test
    void rejectsUnsignedAlgNoneToken() {
        String unsigned = Jwts.builder()
                .subject(claims.userId().toString())
                .claim("role", "ADMIN")
                .compact();
        assertThat(codecAt(key, T0).decode(unsigned)).isEmpty();
    }

    @Test
    void rejectsGarbage() {
        JwtCodec codec = codecAt(key, T0);
        assertThat(codec.decode("not-a-jwt")).isEmpty();
        assertThat(codec.decode("")).isEmpty();
    }

    private static JwtCodec codecAt(SecretKey key, Instant now) {
        return new JwtCodec(key, TTL, Clock.fixed(now, ZoneOffset.UTC));
    }
}
