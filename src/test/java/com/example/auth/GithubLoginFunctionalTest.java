package com.example.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Functional test of the parts of the GitHub flow that don't need GitHub itself:
 * the redirect to GitHub, and rejecting a forged callback. The full browser round trip is a manual check.
 */
@FunctionalTest
@TestPropertySource(properties = {
        "spring.security.oauth2.client.registration.github.client-id=test-client-id",
        "spring.security.oauth2.client.registration.github.client-secret=test-client-secret"
})
class GithubLoginFunctionalTest {

    @Autowired MockMvc mvc;

    @Test
    void startingGithubLoginRedirectsToGithub() throws Exception {
        String location = mvc.perform(get("/oauth2/authorization/github"))
                .andExpect(status().isFound())
                .andReturn().getResponse().getRedirectedUrl();

        assertThat(location)
                .startsWith("https://github.com/login/oauth/authorize")
                .contains("client_id=test-client-id")
                .contains("state=");
    }

    @Test
    void forgedCallbackWithoutMatchingStateIsRejectedWith401() throws Exception {
        // No login was started in this session, so the state can't match: protects against CSRF on login
        mvc.perform(get("/login/oauth2/code/github").param("code", "fake-code").param("state", "fake-state"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.status").value(401));
    }
}
