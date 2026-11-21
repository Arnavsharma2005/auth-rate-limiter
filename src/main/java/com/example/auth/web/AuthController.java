package com.example.auth.web;

import com.example.auth.identity.IdentityService;
import com.example.auth.identity.UserView;
import com.example.auth.ratelimit.RateLimiter;
import com.example.auth.session.SessionService;
import com.example.auth.session.TokenPair;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
class AuthController {

    // BCrypt only uses the first 72 bytes of a password, so longer ones are rejected up front.
    // On login too: otherwise any password that starts with the right 72 bytes would match.
    record RegisterRequest(
            @NotBlank @Email String email,
            @NotBlank @Size(min = 8) @MaxUtf8Bytes(72) String password) {
    }

    record LoginRequest(
            @NotBlank String email,
            @NotBlank @MaxUtf8Bytes(72) String password) {
    }

    record RefreshRequest(@NotBlank String refreshToken) {
    }

    private final IdentityService identity;
    private final SessionService sessions;
    private final RateLimiter limiter;

    AuthController(IdentityService identity, SessionService sessions, RateLimiter limiter) {
        this.identity = identity;
        this.sessions = sessions;
        this.limiter = limiter;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    UserView register(@Valid @RequestBody RegisterRequest request, HttpServletRequest http) {
        // Each registration costs a BCrypt hash and answers "is this email taken?", so it is limited like login
        limit("register", http);
        return identity.register(request.email(), request.password());
    }

    @PostMapping("/login")
    TokenPair login(@Valid @RequestBody LoginRequest request, HttpServletRequest http) {
        limit("login", http);
        return identity.checkPassword(request.email(), request.password())
                .map(sessions::start)
                // Same message for unknown email and wrong password
                .orElseThrow(() -> new ErrorResponseException(HttpStatus.UNAUTHORIZED,
                        ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Invalid credentials"), null));
    }

    @PostMapping("/refresh")
    TokenPair refresh(@Valid @RequestBody RefreshRequest request) {
        return sessions.refresh(request.refreshToken());
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void logout(@Valid @RequestBody RefreshRequest request) {
        sessions.end(request.refreshToken());
    }

    /**
     * Limited inside the handler rather than in a URL filter: any URL spelling that reaches the handler
     * (for example the percent-encoded /auth/%6cogin) uses up the same bucket.
     * getRemoteAddr(), not X-Forwarded-For, because that header can be faked by the client.
     */
    private void limit(String action, HttpServletRequest http) {
        RateLimiter.Decision decision = limiter.tryAcquire(action + ":" + http.getRemoteAddr());
        if (!decision.allowed()) {
            var error = new ErrorResponseException(HttpStatus.TOO_MANY_REQUESTS,
                    ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS, "Too many attempts, try again later"), null);
            error.getHeaders().set(HttpHeaders.RETRY_AFTER, String.valueOf(decision.retryAfterSeconds()));
            throw error;
        }
    }
}
