package com.example.auth.session;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(SessionProperties.class)
class SessionConfig {

    private static final Logger log = LoggerFactory.getLogger(SessionConfig.class);
    private static final int MIN_SECRET_BYTES = 32; // HS256 needs a 256-bit key

    @Bean
    JwtCodec jwtCodec(SessionProperties props) {
        return new JwtCodec(signingKey(props.jwtSecret()), props.accessTtl(), Clock.systemUTC());
    }

    private static SecretKey signingKey(String secret) {
        if (secret == null || secret.isBlank()) {
            log.warn("JWT_SECRET is not set: using a random signing key. Tokens stop working on restart. Dev only.");
            return Jwts.SIG.HS256.key().build();
        }
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException("JWT_SECRET must be at least " + MIN_SECRET_BYTES + " bytes");
        }
        return Keys.hmacShaKeyFor(bytes);
    }
}
