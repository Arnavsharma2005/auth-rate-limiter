package com.example.auth.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.example.auth.IntegrationTest;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

/** Integration test: IdentityService against a real Postgres, schema created by Flyway. */
@IntegrationTest
class IdentityServiceIntegrationTest {

    @Autowired IdentityService identity;
    @Autowired JdbcTemplate jdbc;

    // ---------- GitHub accounts ----------

    @Test
    void firstGithubLoginCreatesAUserWithoutPassword() {
        long githubId = randomGithubId();
        String email = "Octo-" + UUID.randomUUID() + "@Example.com";

        UserView user = identity.findOrCreateGithubUser(githubId, email);

        assertThat(user.role()).isEqualTo(Role.USER);
        assertThat(user.email()).isEqualTo(email.toLowerCase());
        Long storedGithubId = jdbc.queryForObject("SELECT github_id FROM users WHERE id = ?", Long.class, user.id());
        String storedHash = jdbc.queryForObject("SELECT password_hash FROM users WHERE id = ?", String.class, user.id());
        assertThat(storedGithubId).isEqualTo(githubId);
        assertThat(storedHash).isNull();
    }

    @Test
    void repeatGithubLoginReturnsTheSameUser() {
        long githubId = randomGithubId();

        UserView first = identity.findOrCreateGithubUser(githubId, "octo-" + UUID.randomUUID() + "@example.com");
        UserView second = identity.findOrCreateGithubUser(githubId, "octo-" + UUID.randomUUID() + "@example.com");

        assertThat(second.id()).isEqualTo(first.id());
        Integer rows = jdbc.queryForObject("SELECT count(*) FROM users WHERE github_id = ?", Integer.class, githubId);
        assertThat(rows).isEqualTo(1);
    }

    @Test
    void githubUsersWithHiddenEmailAreAllowed() {
        UserView a = identity.findOrCreateGithubUser(randomGithubId(), null);
        UserView b = identity.findOrCreateGithubUser(randomGithubId(), null);

        assertThat(a.email()).isNull();
        assertThat(b.id()).isNotEqualTo(a.id());
    }

    @Test
    void githubEmailOwnedByPasswordAccountIsRejected() {
        String email = "taken-" + UUID.randomUUID() + "@example.com";
        identity.register(email, "correct-horse-battery");

        assertThatThrownBy(() -> identity.findOrCreateGithubUser(randomGithubId(), email.toUpperCase()))
                .isInstanceOf(EmailTakenException.class);
    }

    @Test
    void githubOnlyUserCannotLogInWithAPassword() {
        String email = "octo-" + UUID.randomUUID() + "@example.com";
        identity.findOrCreateGithubUser(randomGithubId(), email);

        assertThat(identity.checkPassword(email, "anything-at-all")).isEmpty();
    }

    // ---------- password accounts ----------

    @Test
    void registerThenCheckPassword() {
        String email = "user-" + UUID.randomUUID() + "@example.com";
        UserView user = identity.register("  " + email.toUpperCase() + "  ", "correct-horse-battery");

        assertThat(user.email()).isEqualTo(email);
        assertThat(identity.checkPassword(email, "correct-horse-battery")).contains(user);
        assertThat(identity.checkPassword(email, "wrong-password")).isEmpty();
    }

    @Test
    void findAndListAll() {
        UserView user = identity.register("user-" + UUID.randomUUID() + "@example.com", "correct-horse-battery");

        assertThat(identity.find(user.id())).contains(user);
        assertThat(identity.find(UUID.randomUUID())).isEmpty();
        assertThat(identity.listAll()).contains(user);
    }

    private static long randomGithubId() {
        return ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
    }
}
