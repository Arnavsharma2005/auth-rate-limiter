package com.example.auth.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.example.auth.identity.IdentityService;
import com.example.auth.ratelimit.RateLimiter;
import com.example.auth.session.SessionService;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.ErrorResponseException;

/** Unit test: the login rate limit inside AuthController, with a fake limiter. No Spring context, no Redis. */
@Tag("unit")
class AuthControllerLoginLimitTest {

    /** Records the keys it was asked about and answers with a fixed decision. */
    static class FakeLimiter implements RateLimiter {
        final List<String> keys = new ArrayList<>();
        final Decision answer;

        FakeLimiter(Decision answer) {
            this.answer = answer;
        }

        @Override
        public Decision tryAcquire(String key) {
            keys.add(key);
            return answer;
        }
    }

    private final IdentityService identity = mock(IdentityService.class);
    private final SessionService sessions = mock(SessionService.class);
    private final AuthController.LoginRequest login =
            new AuthController.LoginRequest("a@example.com", "correct-horse-battery");

    @Test
    void deniedLoginGets429WithRetryAfterAndNoPasswordCheck() {
        FakeLimiter limiter = new FakeLimiter(new RateLimiter.Decision(false, 7));
        AuthController controller = new AuthController(identity, sessions, limiter);

        ErrorResponseException error = catchThrowableOfType(ErrorResponseException.class,
                () -> controller.login(login, from("203.0.113.7")));

        assertThat(limiter.keys).containsExactly("login:203.0.113.7");
        assertThat(error.getStatusCode().value()).isEqualTo(429);
        assertThat(error.getHeaders().getFirst("Retry-After")).isEqualTo("7");
        verifyNoInteractions(identity, sessions);
    }

    @Test
    void allowedLoginGoesOnToCheckThePassword() {
        FakeLimiter limiter = new FakeLimiter(new RateLimiter.Decision(true, 0));
        when(identity.checkPassword(any(), any())).thenReturn(Optional.empty());
        AuthController controller = new AuthController(identity, sessions, limiter);

        ErrorResponseException error = catchThrowableOfType(ErrorResponseException.class,
                () -> controller.login(login, from("203.0.113.7")));

        assertThat(error.getStatusCode().value()).isEqualTo(401);
        verify(identity).checkPassword("a@example.com", "correct-horse-battery");
    }

    private static MockHttpServletRequest from(String ip) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/login");
        request.setRemoteAddr(ip);
        return request;
    }
}
