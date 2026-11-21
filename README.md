# Auth & Rate-Limiting Service

A Spring Boot authentication service with email/password and GitHub login, short-lived JWT access tokens, revocable refresh tokens, role-based access, and a Redis token-bucket rate limiter on login.

**Stack:** Java 21 · Spring Boot 4 · Spring Security · PostgreSQL 16 · Redis 7 · Flyway · jjwt · Docker Compose · JUnit 5 · Testcontainers

---

## Run it

Requirements: Java 21 and Docker. Maven is not needed because the project includes the Maven wrapper.

```bash
docker compose up -d          # Postgres + Redis
./mvnw spring-boot:run        # app on http://localhost:8080
```

Check it's up:

```bash
curl localhost:8080/actuator/health   # {"status":"UP", ... "db":UP, "redis":UP}
```

### Configuration

| Environment variable | Default | Meaning |
|---|---|---|
| `JWT_SECRET` | *(random per start)* | HMAC key for access tokens, **at least 32 bytes**. If it's unset, a random key is used and tokens stop working after a restart (dev only). |
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `localhost` / `5432` / `auth` / `auth` / `auth-dev-password` | Postgres |
| `REDIS_HOST` / `REDIS_PORT` | `localhost` / `6379` | Redis |
| `SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENT_ID` | *(unset)* | Enables GitHub login |
| `SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENT_SECRET` | *(unset)* | Enables GitHub login |

### Enabling GitHub login

1. On GitHub, go to **Settings → Developer settings → OAuth Apps → New OAuth App**.
2. Set the **Homepage URL** to `http://localhost:8080` and the **Authorization callback URL** to `http://localhost:8080/login/oauth2/code/github`.
3. Copy the Client ID, generate a Client Secret, and set both environment variables from the table above.
4. Restart the app, then open `http://localhost:8080/oauth2/authorization/github` in a browser.

Without these variables the app runs normally and GitHub login is simply switched off.

---

## API

| Method & path | Auth | Success | Errors |
|---|---|---|---|
| `POST /auth/register` `{email, password}` | none | **201** `{id, email, role}` | 400 invalid input · 409 email taken |
| `POST /auth/login` `{email, password}` | none, **rate-limited** | **200** `{accessToken, refreshToken, expiresIn}` | 401 invalid credentials · 429 too many attempts (`Retry-After` header) |
| `POST /auth/refresh` `{refreshToken}` | refresh token | **200** new token pair (the old refresh token stops working) | 401 invalid/used/expired |
| `POST /auth/logout` `{refreshToken}` | refresh token | **204** (safe to repeat) | — |
| `GET /api/me` | `Bearer <accessToken>` | **200** `{id, email, role}` | 401 |
| `GET /api/admin/users` | `Bearer`, role **ADMIN** | **200** list of users | 401 · 403 |
| `GET /oauth2/authorization/github` | browser | **200** token pair (after GitHub approves) | 401 failed · 409 email already has a password account |

All errors are [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807) JSON, for example `{"status":401,"title":"Unauthorized","detail":"Invalid credentials"}`.

```bash
curl -X POST localhost:8080/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"a@b.com","password":"correct-horse-battery"}'
curl -X POST localhost:8080/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"a@b.com","password":"correct-horse-battery"}'
curl localhost:8080/api/me -H "Authorization: Bearer <accessToken>"
```

To make a user an admin:
`docker compose exec postgres psql -U auth -d auth -c "UPDATE users SET role='ADMIN' WHERE email='a@b.com'"`.
The new role appears in the user's next access token, after their next login or refresh.

---

## How it works

```
POST /auth/login
   │
   ▼
LoginRateLimitFilter ──► Redis  rl:login:<ip>   (token bucket, Lua script: atomic)
   │  over limit → 429 + Retry-After
   ▼
IdentityService.checkPassword ──► Postgres users (BCrypt)
   │  wrong → 401
   ▼
SessionService.start
   ├─ access token:  JWT HS256, 15 min, claims {sub, role}
   └─ refresh token: 32 random bytes, stored in Redis as refresh:<sha256> → userId, 7 days

GET /api/me  (Authorization: Bearer <JWT>)
   │
   ▼
JwtAuthFilter ── verifies signature + expiry only (no DB, no Redis)
   ▼
Controller
```

### Code layout: one package per responsibility

```
identity/   users table + password hashing        public: IdentityService, UserView, Role
session/    JWT signing + refresh tokens in Redis public: SessionService, TokenPair, AccessClaims
ratelimit/  Redis token bucket (rl:* keys)        public: RateLimiter
web/        HTTP only: controllers, filters, security config, error handling
```

Each package exposes one service. Its internals, such as `UserEntity`, `UserRepository`, `JwtCodec`, `RefreshTokenStore` and `RedisTokenBucket`, are **package-private**, so other packages can't bypass the service. Both password login and GitHub login create tokens through the same method, `SessionService.start`.

### Design decisions

| Decision | Why |
|---|---|
| Short JWT (15 min) + refresh token in Redis | Requests are verified without any database call, and logout is still possible by deleting the refresh token. |
| Refresh tokens are random, not JWTs, and stored **hashed** | Leaked Redis data can't be replayed as tokens. |
| Refresh token **rotation** with `GETDEL` | Each refresh token works once. `GETDEL` is atomic, so two concurrent refreshes can't both succeed. |
| Role re-read on refresh | A role change takes effect within one access-token lifetime. |
| Token bucket in a **Lua script** | The read, refill and take happen in one atomic step, so 20 simultaneous requests can't take more than 5 tokens. |
| Rate limit by `remoteAddr`, not `X-Forwarded-For` | The header can be spoofed by the client (see Limitations). |
| BCrypt check runs even for unknown emails | Response time doesn't reveal which emails are registered. |
| Same 401 for unknown email and wrong password | Prevents account enumeration. |
| GitHub email that matches a password account → 409, not auto-link | Auto-linking unverified emails can be used to take over accounts. |
| Passwords capped at 72 characters | BCrypt ignores everything after 72 bytes. |
| `JWT_SECRET` never committed | Missing → random key (dev). Too short → the app refuses to start. |

### Limitations (known, accepted)

- **Logout leaves a short window.** After logout, the access token keeps working until it expires, at most 15 minutes. A denylist would close that window, but every request would then need a Redis call.
- **Proxies.** Behind a reverse proxy every client has the proxy's IP. To fix this, configure Spring's `ForwardedHeaderFilter` to trust only your proxy.
- **GitHub login returns JSON in the browser.** A real frontend would receive the tokens through a redirect instead.
- **Rate limiting covers login only.** Adding it to another endpoint takes one more filter rule.

---

## Tests

The tests are split into three levels. Every class is tagged with its level, so each level can run on its own.

| Level | What it checks | Needs Docker? | Classes |
|---|---|---|---|
| **Unit** (`@Tag("unit")`) | One class in isolation, with fakes or mocks. No Spring. | No | `JwtCodecTest`, `SessionServiceTest`, `LoginRateLimitFilterTest`, `GithubLoginSuccessHandlerTest` |
| **Integration** (`@IntegrationTest`) | One component against **real** Postgres or Redis (Testcontainers) | Yes | `IdentityServiceIntegrationTest`, `RefreshTokenStoreIntegrationTest`, `RedisTokenBucketIntegrationTest` |
| **Functional** (`@FunctionalTest`) | Whole app through HTTP, the way an API client sees it | Yes | `RegisterFunctionalTest`, `LoginFunctionalTest`, `RefreshLogoutFunctionalTest`, `AdminFunctionalTest`, `RateLimitFunctionalTest`, `GithubLoginFunctionalTest` |

```bash
./mvnw test                          # everything
./mvnw test -Dgroups=unit            # fast, no Docker
./mvnw test -Dgroups=integration
./mvnw test -Dgroups=functional
```

To check a running app end to end (18 checks across every endpoint, including the 429):

```bash
./scripts/smoke-test.sh
```

Some security-critical tests worth reading:

- `JwtCodecTest` rejects expired tokens, tampered tokens, tokens signed with another key, and unsigned `alg: none` tokens.
- `RedisTokenBucketIntegrationTest` fires 20 concurrent requests and checks that exactly 5 are allowed.
- `RefreshTokenStoreIntegrationTest` has 10 threads use one refresh token at once and checks that exactly 1 succeeds.
- `RefreshLogoutFunctionalTest` checks that a used refresh token can't be replayed, and that logout revokes it.
