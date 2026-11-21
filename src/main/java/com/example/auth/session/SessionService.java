package com.example.auth.session;

import com.example.auth.identity.IdentityService;
import com.example.auth.identity.UserView;
import java.util.Optional;
import org.springframework.stereotype.Service;

/** The only place tokens are created or checked. Password login and GitHub login both end in start(). */
@Service
public class SessionService {

    private final JwtCodec jwt;
    private final RefreshTokenStore refreshTokens;
    private final IdentityService identity;

    SessionService(JwtCodec jwt, RefreshTokenStore refreshTokens, IdentityService identity) {
        this.jwt = jwt;
        this.refreshTokens = refreshTokens;
        this.identity = identity;
    }

    public TokenPair start(UserView user) {
        String accessToken = jwt.encode(new AccessClaims(user.id(), user.role()));
        String refreshToken = refreshTokens.create(user.id());
        return new TokenPair(accessToken, refreshToken, jwt.ttl().toSeconds());
    }

    /** Checks signature and expiry only. No database or Redis call, so every request stays fast. */
    public Optional<AccessClaims> authenticate(String accessToken) {
        return jwt.decode(accessToken);
    }

    /**
     * Rotation: the old refresh token is used up and a new pair is issued.
     * The role is read again from the database, so a role change applies on the next refresh.
     */
    public TokenPair refresh(String refreshToken) {
        UserView user = refreshTokens.consume(refreshToken)
                .flatMap(identity::find)
                .orElseThrow(InvalidRefreshTokenException::new);
        return start(user);
    }

    /** Logout. Safe to call twice or with an unknown token. */
    public void end(String refreshToken) {
        refreshTokens.delete(refreshToken);
    }
}
