package com.example.auth.session;

/** What a successful login returns. expiresIn is the access token's lifetime in seconds. */
public record TokenPair(String accessToken, String refreshToken, long expiresIn) {
}
