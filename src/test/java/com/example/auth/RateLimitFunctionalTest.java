package com.example.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
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

    @Test
    void encodedLoginPathSharesTheSameLimit() throws Exception {
        RequestPostProcessor attacker = TestRequests.fromRandomIp();
        for (int i = 1; i <= 5; i++) {
            badLogin(attacker).andExpect(status().isUnauthorized());
        }
        // %6c is "l": the server decodes this to /auth/login and runs the same login code
        badLogin(attacker, URI.create("/auth/%6cogin"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"));
    }

    @Test
    void sixthRegistrationInAMinuteGets429() throws Exception {
        RequestPostProcessor ip = TestRequests.fromRandomIp();
        for (int i = 1; i <= 5; i++) {
            register(ip).andExpect(status().isCreated());
        }
        register(ip)
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"));
        register(TestRequests.fromRandomIp()).andExpect(status().isCreated());
    }

    private ResultActions register(RequestPostProcessor ip) throws Exception {
        return mvc.perform(post("/auth/register").with(ip)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"user-%s@example.com","password":"correct-horse-battery"}""".formatted(UUID.randomUUID())));
    }

    private ResultActions badLogin(RequestPostProcessor ip) throws Exception {
        return badLogin(ip, URI.create("/auth/login"));
    }

    private ResultActions badLogin(RequestPostProcessor ip, URI path) throws Exception {
        return mvc.perform(post(path).with(ip)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {"email":"nobody-%s@example.com","password":"wrong-password"}""".formatted(UUID.randomUUID())));
    }
}
