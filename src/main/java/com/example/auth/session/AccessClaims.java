package com.example.auth.session;

import com.example.auth.identity.Role;
import java.util.UUID;

/** Who the caller is, read from a verified access token. */
public record AccessClaims(UUID userId, Role role) {
}
