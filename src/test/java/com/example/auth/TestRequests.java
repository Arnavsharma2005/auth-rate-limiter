package com.example.auth;

import java.util.concurrent.ThreadLocalRandom;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/** Request helpers shared by functional tests. */
public final class TestRequests {

    private TestRequests() {
    }

    /**
     * A random client IP. The login rate limit is per IP, so giving each test its own IP
     * stops tests from using up each other's login attempts.
     */
    public static RequestPostProcessor fromRandomIp() {
        ThreadLocalRandom r = ThreadLocalRandom.current();
        String ip = "10." + r.nextInt(256) + "." + r.nextInt(256) + "." + r.nextInt(1, 255);
        return fromIp(ip);
    }

    public static RequestPostProcessor fromIp(String ip) {
        return request -> {
            request.setRemoteAddr(ip);
            return request;
        };
    }
}
