package com.example.auth.web;

import com.example.auth.session.AccessClaims;
import com.example.auth.session.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Reads "Authorization: Bearer <token>" and, if the token is valid, marks the request as authenticated.
 * An invalid or missing token is not an error here: the request just stays anonymous, and Spring Security
 * returns 401 if the endpoint needs a login.
 *
 * Not a @Component: SecurityConfig adds it to the security chain, and a @Component would run it twice.
 */
class JwtAuthFilter extends OncePerRequestFilter {

    private static final String BEARER = "Bearer ";

    private final SessionService sessions;

    JwtAuthFilter(SessionService sessions) {
        this.sessions = sessions;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(BEARER)) {
            sessions.authenticate(header.substring(BEARER.length()))
                    .ifPresent(JwtAuthFilter::setAuthenticated);
        }
        chain.doFilter(request, response);
    }

    private static void setAuthenticated(AccessClaims claims) {
        var authority = new SimpleGrantedAuthority("ROLE_" + claims.role().name());
        var authentication = new UsernamePasswordAuthenticationToken(claims, null, List.of(authority));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
