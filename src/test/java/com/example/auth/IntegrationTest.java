package com.example.auth;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.Tag;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

/**
 * Integration test: calls one component directly (no HTTP) against real Postgres and Redis,
 * to check it works with the real database. Run only these with: ./mvnw test -Dgroups=integration
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Tag("integration")
public @interface IntegrationTest {
}
