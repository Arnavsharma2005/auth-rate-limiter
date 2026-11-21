package com.example.auth.web;

import com.example.auth.identity.EmailTakenException;
import com.example.auth.session.InvalidRefreshTokenException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/** Turns exceptions into RFC 7807 ProblemDetail JSON. The base class already covers validation errors (400). */
@RestControllerAdvice
class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(EmailTakenException.class)
    ProblemDetail emailTaken() {
        // Deliberately doesn't echo the email back
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, "Email already registered");
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    ProblemDetail invalidRefreshToken() {
        return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Invalid refresh token");
    }
}
