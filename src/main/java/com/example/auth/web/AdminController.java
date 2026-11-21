package com.example.auth.web;

import com.example.auth.identity.IdentityService;
import com.example.auth.identity.UserView;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
class AdminController {

    private final IdentityService identity;

    AdminController(IdentityService identity) {
        this.identity = identity;
    }

    @GetMapping("/users")
    List<UserView> listUsers() {
        return identity.listAll();
    }
}
