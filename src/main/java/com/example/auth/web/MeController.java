package com.example.auth.web;

import com.example.auth.identity.IdentityService;
import com.example.auth.identity.UserView;
import com.example.auth.session.AccessClaims;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
class MeController {

    private final IdentityService identity;

    MeController(IdentityService identity) {
        this.identity = identity;
    }

    @GetMapping("/api/me")
    UserView me(@AuthenticationPrincipal AccessClaims claims) {
        // 404 if the user was deleted after the token was issued
        return identity.find(claims.userId())
                .orElseThrow(() -> new ErrorResponseException(HttpStatus.NOT_FOUND));
    }
}
