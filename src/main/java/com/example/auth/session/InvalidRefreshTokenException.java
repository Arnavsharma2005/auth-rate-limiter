package com.example.auth.session;

/** The refresh token is unknown, expired, already used, or its user no longer exists. */
public class InvalidRefreshTokenException extends RuntimeException {

    public InvalidRefreshTokenException() {
        super("Invalid refresh token");
    }
}
