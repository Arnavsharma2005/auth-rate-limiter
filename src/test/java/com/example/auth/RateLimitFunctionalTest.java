package com.example.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

@FunctionalTest
class RateLimitFunctionalTest {

    @Autowired MockMvc mvc;

    @Test
    void sixthLoginAttemptInAMinuteGets429() throws Exception {
        RequestPostProcessor attacker = TestRequests.fromRandomIp();
        for (int i = 1; i <= 5; i++) {
            badLogin(attacker).andExpect(status().isUnauthorized());
        }
        badLogin(attacker)
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "12"))
                .andExpect(jsonPath("$.status").value(429));
    }

    @Test
    void anotherIpIsNotAffected() throws Exception {
        RequestPostProcessor attacker = TestRequests.fromRandomIp();
        for (int i = 1; i <= 6; i++) {
            badLogin(attacker);
        }
        badLogin(TestRequests.fromRandomIp()).andExpect(status().isUnauthorized());
    }

    private ResultActions badLogin(RequestPostProcessor ip) throws Exception {
        return mvc.perform(post("/auth/login").with(ip)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"nobody-%s@example.com","password":"wrong-password"}""".formatted(UUID.randomUUID())));
    }
}
