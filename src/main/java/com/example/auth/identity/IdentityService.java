package com.example.auth.identity;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** The only way to read or change users. Owns the users table and password hashing. */
@Service
public class IdentityService {

    private final UserRepository users;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    // Compared against when the email is unknown, so a miss costs the same time as a wrong password.
    private final String dummyHash = passwordEncoder.encode("timing-equalizer");

    IdentityService(UserRepository users) {
        this.users = users;
    }

    @Transactional
    public UserView register(String email, String rawPassword) {
        String normalized = normalize(email);
        if (users.existsByEmail(normalized)) {
            throw new EmailTakenException(normalized);
        }
        try {
            UserEntity saved = users.saveAndFlush(
                    UserEntity.withPassword(normalized, passwordEncoder.encode(rawPassword)));
            return UserView.of(saved);
        } catch (DataIntegrityViolationException e) {
            // Two requests registered the same email at once; the unique constraint caught the second.
            throw new EmailTakenException(normalized);
        }
    }

    /** Empty if the email is unknown or the password is wrong; the caller can't tell which. */
    @Transactional(readOnly = true)
    public Optional<UserView> checkPassword(String email, String rawPassword) {
        Optional<UserEntity> user = users.findByEmail(normalize(email));
        String hash = user.map(UserEntity::getPasswordHash).orElse(null);
        if (hash == null) {
            passwordEncoder.matches(rawPassword, dummyHash);
            return Optional.empty();
        }
        return passwordEncoder.matches(rawPassword, hash) ? user.map(UserView::of) : Optional.empty();
    }

    /**
     * Returns the user linked to this GitHub account, creating a USER on first login.
     * Throws EmailTakenException if the GitHub email already belongs to another account
     * (accounts are not linked automatically, because that can be used to take over accounts).
     */
    @Transactional
    public UserView findOrCreateGithubUser(long githubId, String email) {
        Optional<UserEntity> existing = users.findByGithubId(githubId);
        if (existing.isPresent()) {
            return UserView.of(existing.get());
        }
        String normalized = email == null ? null : normalize(email);
        if (normalized != null && users.existsByEmail(normalized)) {
            throw new EmailTakenException(normalized);
        }
        try {
            return UserView.of(users.saveAndFlush(UserEntity.withGithub(githubId, normalized)));
        } catch (DataIntegrityViolationException e) {
            // Lost a race with a concurrent signup. Only the email case is a user-facing conflict.
            if (normalized != null && String.valueOf(e.getMessage()).contains("users_email_key")) {
                throw new EmailTakenException(normalized);
            }
            throw e;
        }
    }

    @Transactional(readOnly = true)
    public Optional<UserView> find(UUID id) {
        return users.findById(id).map(UserView::of);
    }

    @Transactional(readOnly = true)
    public List<UserView> listAll() {
        return users.findAll().stream().map(UserView::of).toList();
    }

    private static String normalize(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
