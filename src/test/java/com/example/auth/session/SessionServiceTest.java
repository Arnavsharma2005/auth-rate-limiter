package com.example.auth.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.example.auth.identity.IdentityService;
import com.example.auth.identity.Role;
import com.example.auth.identity.UserView;
import io.jsonwebtoken.Jwts;
import java.time.Clock;
import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** Unit test: SessionService with a real JwtCodec and mocked storage. No Spring, no Redis. */
@Tag("unit")
class SessionServiceTest {

    private final JwtCodec jwt = new JwtCodec(Jwts.SIG.HS256.key().build(), Duration.ofMinutes(15), Clock.systemUTC());
    private final RefreshTokenStore store = mock(RefreshTokenStore.class);
    private final IdentityService identity = mock(IdentityService.class);
    private final SessionService sessions = new SessionService(jwt, store, identity);

    private final UserView user = new UserView(UUID.randomUUID(), "a@example.com", Role.USER);

    @Test
    void startIssuesAccessTokenForTheUserAndAStoredRefreshToken() {
        when(store.create(user.id())).thenReturn("refresh-1");

        TokenPair pair = sessions.start(user);

        assertThat(pair.refreshToken()).isEqualTo("refresh-1");
        assertThat(pair.expiresIn()).isEqualTo(900);
        assertThat(sessions.authenticate(pair.accessToken())).contains(new AccessClaims(user.id(), Role.USER));
    }

    @Test
    void refreshUsesUpTheOldTokenAndReadsTheCurrentRole() {
        UserView promoted = new UserView(user.id(), user.email(), Role.ADMIN);
        when(store.consume("old")).thenReturn(Optional.of(user.id()));
        when(identity.find(user.id())).thenReturn(Optional.of(promoted));
        when(store.create(user.id())).thenReturn("new");

        TokenPair pair = sessions.refresh("old");

        assertThat(pair.refreshToken()).isEqualTo("new");
        assertThat(sessions.authenticate(pair.accessToken()))
                .map(AccessClaims::role).contains(Role.ADMIN);
    }

    @Test
    void refreshWithUnknownTokenFailsWithoutIssuingTokens() {
        when(store.consume("unknown")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> sessions.refresh("unknown")).isInstanceOf(InvalidRefreshTokenException.class);
        verify(store, never()).create(any());
    }

    @Test
    void refreshForADeletedUserFails() {
        when(store.consume("orphan")).thenReturn(Optional.of(user.id()));
        when(identity.find(user.id())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> sessions.refresh("orphan")).isInstanceOf(InvalidRefreshTokenException.class);
        verify(store, never()).create(any());
    }

    @Test
    void endDeletesTheRefreshToken() {
        sessions.end("some-token");
        verify(store).delete("some-token");
    }
}
