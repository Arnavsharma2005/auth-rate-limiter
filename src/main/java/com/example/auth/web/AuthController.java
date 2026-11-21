package com.example.auth.web;

import com.example.auth.identity.IdentityService;
import com.example.auth.identity.UserView;
import com.example.auth.session.SessionService;
import com.example.auth.session.TokenPair;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
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
    record RegisterRequest(
            @NotBlank @Email String email,
            @NotBlank @Size(min = 8, max = 72) String password) {
    }

    record LoginRequest(
            @NotBlank String email,
            @NotBlank @Size(max = 72) String password) {
    }

    record RefreshRequest(@NotBlank String refreshToken) {
    }

    private final IdentityService identity;
    private final SessionService sessions;

    AuthController(IdentityService identity, SessionService sessions) {
        this.identity = identity;
        this.sessions = sessions;
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    UserView register(@Valid @RequestBody RegisterRequest request) {
        return identity.register(request.email(), request.password());
    }

    @PostMapping("/login")
    TokenPair login(@Valid @RequestBody LoginRequest request) {
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
}
