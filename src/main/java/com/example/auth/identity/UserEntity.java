package com.example.auth.identity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

// Package-private on purpose: code outside identity must go through IdentityService.
@Entity
@Table(name = "users")
class UserEntity {

    @Id
    private UUID id;

    @Column(columnDefinition = "text")
    private String email;

    @Column(name = "password_hash", columnDefinition = "text")
    private String passwordHash;

    @Column(name = "github_id")
    private Long githubId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, columnDefinition = "text")
    private Role role;

    // Filled by the database default now()
    @Column(name = "created_at", insertable = false, updatable = false)
    private Instant createdAt;

    protected UserEntity() {
        // for JPA
    }

    static UserEntity withPassword(String email, String passwordHash) {
        UserEntity user = new UserEntity();
        user.id = UUID.randomUUID();
        user.email = email;
        user.passwordHash = passwordHash;
        user.role = Role.USER;
        return user;
    }

    static UserEntity withGithub(long githubId, String email) {
        UserEntity user = new UserEntity();
        user.id = UUID.randomUUID();
        user.email = email;
        user.githubId = githubId;
        user.role = Role.USER;
        return user;
    }

    UUID getId() {
        return id;
    }

    String getEmail() {
        return email;
    }

    String getPasswordHash() {
        return passwordHash;
    }

    Role getRole() {
        return role;
    }
}
