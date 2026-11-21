package com.example.auth.web;

import static org.assertj.core.api.Assertions.assertThat;

import com.example.auth.ratelimit.RateLimiter;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/** Unit test: the filter alone, with a fake limiter. No Spring context, no Redis. */
@Tag("unit")
class LoginRateLimitFilterTest {

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

    @Test
    void deniedLoginGets429WithRetryAfterAndStopsTheChain() throws Exception {
        FakeLimiter limiter = new FakeLimiter(new RateLimiter.Decision(false, 7));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new LoginRateLimitFilter(limiter).doFilter(loginFrom("203.0.113.7"), response, chain);

        assertThat(limiter.keys).containsExactly("login:203.0.113.7");
        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getHeader("Retry-After")).isEqualTo("7");
        assertThat(response.getContentType()).isEqualTo("application/problem+json");
        assertThat(response.getContentAsString()).contains("\"status\":429");
        assertThat(chain.getRequest()).as("controller must not run").isNull();
    }

    @Test
    void allowedLoginContinues() throws Exception {
        FakeLimiter limiter = new FakeLimiter(new RateLimiter.Decision(true, 0));
        MockFilterChain chain = new MockFilterChain();

        new LoginRateLimitFilter(limiter).doFilter(loginFrom("203.0.113.7"), new MockHttpServletResponse(), chain);

        assertThat(chain.getRequest()).isNotNull();
    }

    @Test
    void otherEndpointsAreNotLimited() throws Exception {
        FakeLimiter limiter = new FakeLimiter(new RateLimiter.Decision(false, 7));
        LoginRateLimitFilter filter = new LoginRateLimitFilter(limiter);

        for (MockHttpServletRequest request : List.of(
                new MockHttpServletRequest("POST", "/auth/register"),
                new MockHttpServletRequest("GET", "/auth/login"),
                new MockHttpServletRequest("GET", "/api/me"))) {
            MockFilterChain chain = new MockFilterChain();
            filter.doFilter(request, new MockHttpServletResponse(), chain);
            assertThat(chain.getRequest()).as(request.getMethod() + " " + request.getRequestURI()).isNotNull();
        }
        assertThat(limiter.keys).isEmpty();
    }

    private static MockHttpServletRequest loginFrom(String ip) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/login");
        request.setRemoteAddr(ip);
        return request;
    }
}
