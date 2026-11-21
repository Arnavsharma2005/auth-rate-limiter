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
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

@FunctionalTest
class RefreshLogoutFunctionalTest {

    private static final String PASSWORD = "correct-horse-battery";

    @Autowired MockMvc mvc;
    @Autowired IdentityService identity;
    @Autowired JdbcTemplate jdbc;

    private UserView user;
    private final RequestPostProcessor clientIp = TestRequests.fromRandomIp();

    @BeforeEach
    void createUser() {
        user = identity.register("user-" + UUID.randomUUID() + "@example.com", PASSWORD);
    }

    @Test
    void refreshIssuesAWorkingNewPair() throws Exception {
        String oldRefresh = JsonPath.read(loginBody(), "$.refreshToken");

        String body = postToken("/auth/refresh", oldRefresh).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String newAccess = JsonPath.read(body, "$.accessToken");
        String newRefresh = JsonPath.read(body, "$.refreshToken");
        assertThat(newRefresh).isNotEqualTo(oldRefresh);
        mvc.perform(get("/api/me").header(HttpHeaders.AUTHORIZATION, "Bearer " + newAccess))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(user.id().toString()));
    }

    @Test
    void refreshTokenWorksOnlyOnce() throws Exception {
        String refresh = JsonPath.read(loginBody(), "$.refreshToken");

        postToken("/auth/refresh", refresh).andExpect(status().isOk());
        postToken("/auth/refresh", refresh)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid refresh token"));
    }

    @Test
    void replayingAUsedRefreshTokenEndsTheWholeSession() throws Exception {
        String first = JsonPath.read(loginBody(), "$.refreshToken");
        String second = JsonPath.read(postToken("/auth/refresh", first).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(), "$.refreshToken");

        // Someone replays the used token: it must fail, and the token issued in its place must stop working too
        postToken("/auth/refresh", first).andExpect(status().isUnauthorized());
        postToken("/auth/refresh", second).andExpect(status().isUnauthorized());
    }

    @Test
    void logoutRevokesTheRefreshTokenAndCanBeRepeated() throws Exception {
        String refresh = JsonPath.read(loginBody(), "$.refreshToken");

        postToken("/auth/logout", refresh).andExpect(status().isNoContent());
        postToken("/auth/refresh", refresh).andExpect(status().isUnauthorized());
        postToken("/auth/logout", refresh).andExpect(status().isNoContent());
    }

    @Test
    void roleChangeAppliesOnNextRefresh() throws Exception {
        String refresh = JsonPath.read(loginBody(), "$.refreshToken");
        jdbc.update("UPDATE users SET role = 'ADMIN' WHERE id = ?", user.id());

        String body = postToken("/auth/refresh", refresh).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String accessToken = JsonPath.read(body, "$.accessToken");
        String payloadJson = new String(Base64.getUrlDecoder().decode(accessToken.split("\\.")[1]),
                StandardCharsets.UTF_8);
        assertThat((String) JsonPath.read(payloadJson, "$.role")).isEqualTo("ADMIN");
    }

    @Test
    void badRefreshRequestsAreRejected() throws Exception {
        postToken("/auth/refresh", "made-up-token").andExpect(status().isUnauthorized());
        mvc.perform(post("/auth/refresh").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }

    private String loginBody() throws Exception {
        return mvc.perform(post("/auth/login").with(clientIp)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"%s"}""".formatted(user.email(), PASSWORD)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    private ResultActions postToken(String path, String refreshToken) throws Exception {
        return mvc.perform(post(path)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"refreshToken":"%s"}""".formatted(refreshToken)));
    }
}
