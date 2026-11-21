package com.example.auth.web;

import com.example.auth.identity.IdentityService;
import com.example.auth.ratelimit.RateLimiter;
import com.example.auth.session.SessionService;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import tools.jackson.databind.json.JsonMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableMethodSecurity // turns on @PreAuthorize
class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, SessionService sessions, RateLimiter loginRateLimiter,
            IdentityService identity, JsonMapper json, ObjectProvider<ClientRegistrationRepository> oauthClients)
            throws Exception {
        // GitHub login is switched on only when GitHub credentials are configured (see README)
        if (oauthClients.getIfAvailable() != null) {
            http.oauth2Login(oauth -> oauth
                    .successHandler(new GithubLoginSuccessHandler(identity, sessions, json))
                    // Default would redirect to a /login page this API doesn't have
                    .failureHandler((request, response, ex) -> writeProblem(response,
                            HttpStatus.UNAUTHORIZED, "GitHub login failed")));
        }
        return http
                .csrf(csrf -> csrf.disable()) // no cookies: tokens travel in the Authorization header
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/error").permitAll()
                        // refresh and logout are authorized by the refresh token in the body, not an access token
                        .requestMatchers(HttpMethod.POST,
                                "/auth/register", "/auth/login", "/auth/refresh", "/auth/logout").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(new LoginRateLimitFilter(loginRateLimiter), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtAuthFilter(sessions), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(e -> e
                        // Without this, a missing/invalid token gets 403 instead of 401
                        .authenticationEntryPoint((request, response, ex) -> writeProblem(response,
                                HttpStatus.UNAUTHORIZED, "Missing or invalid access token"))
                        .accessDeniedHandler((request, response, ex) -> writeProblem(response,
                                HttpStatus.FORBIDDEN, "You don't have permission for this")))
                .build();
    }

    static void writeProblem(HttpServletResponse response, HttpStatus status, String detail) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.getWriter().write("""
                {"status":%d,"title":"%s","detail":"%s"}""".formatted(status.value(), status.getReasonPhrase(), detail));
    }
}
