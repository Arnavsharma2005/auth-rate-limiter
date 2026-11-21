package com.example.auth.web;

import com.example.auth.ratelimit.RateLimiter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Limits POST /auth/login per client IP, before the password is even checked.
 * Uses getRemoteAddr(), not X-Forwarded-For, because that header can be faked by the client.
 * Not a @Component: SecurityConfig adds it to the security chain.
 */
class LoginRateLimitFilter extends OncePerRequestFilter {

    private final RateLimiter limiter;

    LoginRateLimitFilter(RateLimiter limiter) {
        this.limiter = limiter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !("POST".equals(request.getMethod()) && "/auth/login".equals(request.getRequestURI()));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        RateLimiter.Decision decision = limiter.tryAcquire("login:" + request.getRemoteAddr());
        if (!decision.allowed()) {
            response.setHeader(HttpHeaders.RETRY_AFTER, String.valueOf(decision.retryAfterSeconds()));
            SecurityConfig.writeProblem(response, HttpStatus.TOO_MANY_REQUESTS, "Too many login attempts");
            return;
        }
        chain.doFilter(request, response);
    }
}
