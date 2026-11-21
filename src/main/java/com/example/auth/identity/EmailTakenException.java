package com.example.auth.identity;

public class EmailTakenException extends RuntimeException {

    public EmailTakenException(String email) {
        super("Email already registered: " + email);
    }
}
