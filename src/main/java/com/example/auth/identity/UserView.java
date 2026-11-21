package com.example.auth.identity;

import java.util.UUID;

/** The only user shape that leaves the identity package. Never contains the password hash. */
public record UserView(UUID id, String email, Role role) {

    static UserView of(UserEntity entity) {
        return new UserView(entity.getId(), entity.getEmail(), entity.getRole());
    }
}
