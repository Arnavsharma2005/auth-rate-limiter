package com.example.auth.web;

import com.example.auth.identity.EmailTakenException;
import com.example.auth.identity.IdentityService;
import com.example.auth.identity.UserView;
import com.example.auth.session.SessionService;
import com.example.auth.session.TokenPair;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import tools.jackson.databind.json.JsonMapper;

/**
 * After GitHub approves the login: find or create our user, then answer with our own token pair,
 * the same one /auth/login returns. GitHub's token is never given to the client.
 */
class GithubLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final IdentityService identity;
    private final SessionService sessions;
    private final JsonMapper json;

    GithubLoginSuccessHandler(IdentityService identity, SessionService sessions, JsonMapper json) {
        this.identity = identity;
        this.sessions = sessions;
        this.json = json;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException {
        OAuth2User githubUser = (OAuth2User) authentication.getPrincipal();
        long githubId = ((Number) githubUser.getAttribute("id")).longValue();
        String email = githubUser.getAttribute("email"); // null when the user hides it on GitHub

        UserView user;
        try {
            user = identity.findOrCreateGithubUser(githubId, email);
        } catch (EmailTakenException e) {
            SecurityConfig.writeProblem(response, HttpStatus.CONFLICT,
                    "This email already has a password account. Log in with your password instead.");
            return;
        }

        TokenPair tokens = sessions.start(user);
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(json.writeValueAsString(tokens));
    }
}
