package com.example.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.identity.IdentityService;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

@FunctionalTest
class RegisterFunctionalTest {

    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired IdentityService identity;

    @Test
    void registerStoresBcryptHashNotThePassword() throws Exception {
        String email = uniqueEmail();

        register(email, "correct-horse-battery")
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        String stored = jdbc.queryForObject("SELECT password_hash FROM users WHERE email = ?", String.class, email);
        assertThat(stored).startsWith("$2a$").doesNotContain("correct-horse-battery");
    }

    @Test
    void duplicateEmailIsRejectedEvenWithDifferentCase() throws Exception {
        String email = uniqueEmail();
        register(email, "correct-horse-battery").andExpect(status().isCreated());

        register(email.toUpperCase(), "another-password")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.detail").value("Email already registered"));
    }

    @Test
    void invalidInputIsRejected() throws Exception {
        register("not-an-email", "correct-horse-battery").andExpect(status().isBadRequest());
        register(uniqueEmail(), "short").andExpect(status().isBadRequest());
    }

    @Test
    void checkPasswordAcceptsOnlyTheRightPassword() throws Exception {
        String email = uniqueEmail();
        register(email, "correct-horse-battery").andExpect(status().isCreated());

        assertThat(identity.checkPassword(email, "correct-horse-battery")).isPresent();
        assertThat(identity.checkPassword(email, "wrong-password")).isEmpty();
        assertThat(identity.checkPassword("nobody@example.com", "correct-horse-battery")).isEmpty();
    }

    @Test
    void passwordOver72BytesIsRejected() throws Exception {
        // 40 characters but 80 bytes in UTF-8: BCrypt's limit is in bytes
        register(uniqueEmail(), "é".repeat(40)).andExpect(status().isBadRequest());
    }

    private ResultActions register(String email, String password) throws Exception {
        return mvc.perform(post("/auth/register").with(TestRequests.fromRandomIp())
                .contentType(MediaType.APPLICATION_JSON).characterEncoding(StandardCharsets.UTF_8)
                .content("""
                        {"email":"%s","password":"%s"}""".formatted(email, password)));
    }

    private static String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@example.com";
    }
}
