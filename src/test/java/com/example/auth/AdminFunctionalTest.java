package com.example.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.auth.identity.IdentityService;
import com.example.auth.identity.UserView;
import com.jayway.jsonpath.JsonPath;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

@FunctionalTest
class AdminFunctionalTest {

    private static final String PASSWORD = "correct-horse-battery";

    @Autowired MockMvc mvc;
    @Autowired IdentityService identity;
    @Autowired JdbcTemplate jdbc;

    private final RequestPostProcessor clientIp = TestRequests.fromRandomIp();
    private UserView normalUser;
    private UserView adminUser;

    @BeforeEach
    void createUsers() {
        normalUser = identity.register("user-" + UUID.randomUUID() + "@example.com", PASSWORD);
        adminUser = identity.register("admin-" + UUID.randomUUID() + "@example.com", PASSWORD);
        jdbc.update("UPDATE users SET role = 'ADMIN' WHERE id = ?", adminUser.id());
    }

    @Test
    void adminCanListUsers() throws Exception {
        mvc.perform(get("/api/admin/users").header(HttpHeaders.AUTHORIZATION, bearer(adminUser)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.email == '%s')].role".formatted(adminUser.email())).value("ADMIN"))
                .andExpect(jsonPath("$[?(@.email == '%s')].role".formatted(normalUser.email())).value("USER"))
                .andExpect(jsonPath("$[*].passwordHash").isEmpty());
    }

    @Test
    void normalUserIsForbidden() throws Exception {
        mvc.perform(get("/api/admin/users").header(HttpHeaders.AUTHORIZATION, bearer(normalUser)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.title").value("Forbidden"));
    }

    @Test
    void anonymousIsUnauthorized() throws Exception {
        mvc.perform(get("/api/admin/users")).andExpect(status().isUnauthorized());
    }

    private String bearer(UserView user) throws Exception {
        String body = mvc.perform(post("/auth/login").with(clientIp)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"%s"}""".formatted(user.email(), PASSWORD)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return "Bearer " + JsonPath.read(body, "$.accessToken");
    }
}
