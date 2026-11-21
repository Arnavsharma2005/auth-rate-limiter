package com.example.auth.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.ArgumentMatchers.any;

import com.example.auth.identity.EmailTakenException;
import com.example.auth.identity.IdentityService;
import com.example.auth.identity.Role;
import com.example.auth.identity.UserView;
import com.example.auth.session.SessionService;
import com.example.auth.session.TokenPair;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import tools.jackson.databind.json.JsonMapper;

/** Unit test: the handler alone, with mocked services. No Spring context, no database. */
@Tag("unit")
class GithubLoginSuccessHandlerTest {

    private final IdentityService identity = mock(IdentityService.class);
    private final SessionService sessions = mock(SessionService.class);
    private final GithubLoginSuccessHandler handler =
            new GithubLoginSuccessHandler(identity, sessions, JsonMapper.builder().build());

    @Test
    void returnsOurOwnTokenPairForTheGithubUser() throws Exception {
        UserView user = new UserView(UUID.randomUUID(), "octo@example.com", Role.USER);
        when(identity.findOrCreateGithubUser(583231L, "octo@example.com")).thenReturn(user);
        when(sessions.start(user)).thenReturn(new TokenPair("access-123", "refresh-456", 900));
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, githubLogin(583231, "octo@example.com"));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentType()).startsWith("application/json");
        assertThat(response.getContentAsString())
                .contains("\"accessToken\":\"access-123\"")
                .contains("\"refreshToken\":\"refresh-456\"")
                .contains("\"expiresIn\":900");
    }

    @Test
    void hiddenGithubEmailIsPassedAsNull() throws Exception {
        UserView user = new UserView(UUID.randomUUID(), null, Role.USER);
        when(identity.findOrCreateGithubUser(42L, null)).thenReturn(user);
        when(sessions.start(user)).thenReturn(new TokenPair("a", "r", 900));
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, githubLogin(42, null));

        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void emailOwnedByAnotherAccountGets409AndNoTokens() throws Exception {
        when(identity.findOrCreateGithubUser(7L, "taken@example.com"))
                .thenThrow(new EmailTakenException("taken@example.com"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, githubLogin(7, "taken@example.com"));

        assertThat(response.getStatus()).isEqualTo(409);
        assertThat(response.getContentAsString()).contains("\"status\":409");
        verify(sessions, never()).start(any());
    }

    /** What Spring Security hands the handler after a GitHub login. GitHub sends "id" as a number. */
    private static OAuth2AuthenticationToken githubLogin(int githubId, String email) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("id", githubId);
        attributes.put("login", "octocat");
        attributes.put("email", email);
        var authorities = List.of(new SimpleGrantedAuthority("OAUTH2_USER"));
        return new OAuth2AuthenticationToken(new DefaultOAuth2User(authorities, attributes, "id"), authorities, "github");
    }
}
