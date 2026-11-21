package com.example.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.identity.IdentityService;
import com.example.auth.identity.UserView;
import com.jayway.jsonpath.JsonPath;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

@FunctionalTest
class LoginFunctionalTest {

    private static final String PASSWORD = "correct-horse-battery";

    @Autowired MockMvc mvc;
    @Autowired IdentityService identity;
    @Autowired StringRedisTemplate redis;

    private UserView user;
    private final RequestPostProcessor clientIp = TestRequests.fromRandomIp();

    @BeforeEach
    void createUser() {
        user = identity.register("user-" + UUID.randomUUID() + "@example.com", PASSWORD);
    }

    @Test
    void loginReturnsTokenPair() throws Exception {
        login(user.email(), PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString())
                .andExpect(jsonPath("$.expiresIn").value(900));
    }

    @Test
    void refreshTokenIsStoredHashedWithTtl() throws Exception {
        String refreshToken = JsonPath.read(loginBody(), "$.refreshToken");

        String hashedKey = "refresh:" + sha256Hex(refreshToken);
        String sessionId = redis.opsForValue().get(hashedKey);
        assertThat(redis.opsForValue().get("session:" + sessionId)).isEqualTo(user.id().toString());
        assertThat(redis.getExpire(hashedKey)).isPositive();
        assertThat(redis.hasKey("refresh:" + refreshToken)).isFalse();
    }

    @Test
    void wrongPasswordAndUnknownEmailGetTheSame401() throws Exception {
        login(user.email(), "wrong-password")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid credentials"));
        login("nobody-" + UUID.randomUUID() + "@example.com", PASSWORD)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid credentials"));
    }

    @Test
    void meRequiresAValidAccessToken() throws Exception {
        mvc.perform(get("/api/me")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/me").header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt"))
                .andExpect(status().isUnauthorized());

        String accessToken = JsonPath.read(loginBody(), "$.accessToken");
        mvc.perform(get("/api/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(user.id().toString()))
                .andExpect(jsonPath("$.email").value(user.email()))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    void passwordThatOnlyMatchesTheFirst72BytesIsRejected() throws Exception {
        String email = "user-" + UUID.randomUUID() + "@example.com";
        String password = "é".repeat(36); // exactly 72 bytes
        identity.register(email, password);

        login(email, password + "x").andExpect(status().isBadRequest());
        login(email, password).andExpect(status().isOk());
    }

    private ResultActions login(String email, String password) throws Exception {
        return mvc.perform(post("/auth/login").with(clientIp)
                .contentType(MediaType.APPLICATION_JSON).characterEncoding(StandardCharsets.UTF_8)
                .content("""
                        {"email":"%s","password":"%s"}""".formatted(email, password)));
    }

    private String loginBody() throws Exception {
        return login(user.email(), PASSWORD).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private static String sha256Hex(String value) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash);
    }
}
