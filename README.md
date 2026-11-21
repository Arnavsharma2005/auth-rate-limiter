# Auth & Rate-Limiting Service

[![CI](https://github.com/Arnavsharma2005/auth-rate-limiter/actions/workflows/ci.yml/badge.svg)](https://github.com/Arnavsharma2005/auth-rate-limiter/actions/workflows/ci.yml)

A Spring Boot authentication service. Users sign in with an email and password or with GitHub and get a short-lived JWT plus a refresh token. Login and registration are rate-limited per IP.

**Stack:** Java 21 · Spring Boot 4 · Spring Security · PostgreSQL 16 · Redis 7 · Flyway · jjwt · Docker · GitHub Actions · JUnit 5 · Testcontainers

## Highlights

- **Refresh tokens are used up atomically.** A Lua script in Redis consumes each token in one step. A test sends one token from 10 threads at once, and exactly one request succeeds.
- **A stolen refresh token gets caught.** If a used token comes back, the whole session ends, so the attacker's copy and the real user's new token both stop working.
- **The rate limiter can't be raced.** A Redis token bucket, also in Lua, allows 5 attempts a minute. A test fires 20 concurrent requests and exactly 5 get through.
- **No account enumeration on login.** Unknown emails and wrong passwords get the same 401 in about the same time, because BCrypt runs either way.
- **63 tests at three levels.** Unit tests, integration tests against real Postgres and Redis, and full HTTP tests, all run by CI on every push.

---

## Run it

Requirements: Java 21 and Docker. Maven isn't needed, because the project includes the Maven wrapper.

```bash
docker compose up -d          # Postgres + Redis
./mvnw spring-boot:run        # app on http://localhost:8080
curl localhost:8080/actuator/health   # "status":"UP", with db and redis both UP
```

### Run the Docker image

CI publishes an image for every commit on `main`. It contains only the app, so point it at your Postgres and Redis:

```bash
docker run -p 8080:8080 \
  -e DB_HOST=<postgres host> -e DB_PASSWORD=<password> \
  -e REDIS_HOST=<redis host> -e REDIS_PASSWORD=<password> \
  -e JWT_SECRET=<at least 32 random bytes> \
  ghcr.io/arnavsharma2005/auth-rate-limiter:latest
```

To build it yourself: `docker build -t auth-service .`

### Configuration

| Environment variable | Default | Meaning |
|---|---|---|
| `JWT_SECRET` | *(random per start)* | HMAC key for access tokens, **at least 32 bytes**. If it's unset, a random key is used and tokens stop working after a restart (dev only). |
| `DB_HOST` / `DB_PORT` / `DB_NAME` / `DB_USER` / `DB_PASSWORD` | `localhost` / `5432` / `auth` / `auth` / `auth-dev-password` | Postgres |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD` | `localhost` / `6379` / `redis-dev-password` | Redis. Docker Compose starts Redis with the same password. |
| `SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENT_ID` | *(unset)* | Enables GitHub login |
| `SPRING_SECURITY_OAUTH2_CLIENT_REGISTRATION_GITHUB_CLIENT_SECRET` | *(unset)* | Enables GitHub login |

`docker compose` publishes Postgres and Redis on `127.0.0.1` only, so other machines on your network can't reach them. The default passwords are for local development only. Set `DB_PASSWORD` and `REDIS_PASSWORD` everywhere else, because write access to Redis is enough to create a session for any user.

### Enabling GitHub login

1. On GitHub, go to **Settings → Developer settings → OAuth Apps → New OAuth App**.
2. Set the **Homepage URL** to `http://localhost:8080` and the **Authorization callback URL** to `http://localhost:8080/login/oauth2/code/github`.
3. Copy the Client ID, generate a Client Secret, and set both environment variables from the table above.
4. Restart the app, then open `http://localhost:8080/oauth2/authorization/github` in a browser.

Without these variables the app runs normally with GitHub login switched off.

---

## API

| Method & path | Auth | Success | Errors |
|---|---|---|---|
| `POST /auth/register` `{email, password}` | none, **rate-limited** | **201** `{id, email, role}` | 400 invalid input · 409 email taken · 429 too many attempts |
| `POST /auth/login` `{email, password}` | none, **rate-limited** | **200** `{accessToken, refreshToken, expiresIn}` | 401 invalid credentials · 429 too many attempts (`Retry-After` header) |
| `POST /auth/refresh` `{refreshToken}` | refresh token | **200** new token pair (the old refresh token stops working) | 401 invalid, used or expired. Sending a used token also ends its session. |
| `POST /auth/logout` `{refreshToken}` | refresh token | **204** ends the session (safe to repeat) | — |
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

```bash
docker compose exec postgres psql -U auth -d auth -c "UPDATE users SET role='ADMIN' WHERE email='a@b.com'"
```

The new role appears in the user's next access token, after their next login or refresh.

---

## How it works

```
POST /auth/login
   │
   ▼
AuthController.login: rate limit first ──► Redis  rl:login:<ip>   (token bucket, Lua script: atomic)
   │  over limit → 429 + Retry-After
   ▼
IdentityService.checkPassword ──► Postgres users (BCrypt)
   │  wrong → 401
   ▼
SessionService.start
   ├─ access token:  JWT HS256, 15 min, claims {sub, role}
   ├─ session:       Redis session:<id> → userId, ends 30 days after login
   └─ refresh token: 32 random bytes, stored in Redis as refresh:<sha256> → session id, 7 days

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
session/    JWT signing + sessions in Redis       public: SessionService, TokenPair, AccessClaims
ratelimit/  Redis token bucket (rl:* keys)        public: RateLimiter
web/        HTTP only: controllers, filters, security config, error handling
```

Each package exposes one service. Its internals, such as `UserEntity`, `UserRepository`, `JwtCodec`, `RefreshTokenStore` and `RedisTokenBucket`, are **package-private**, so other packages can't bypass the service. Password login and GitHub login both create tokens through the same method, `SessionService.start`.

### Design decisions

| Decision | Why |
|---|---|
| Short JWT (15 min) + refresh token in Redis | Requests are verified without any database call, and logout still works by deleting the session. |
| Refresh tokens are random, not JWTs, and stored **hashed** | Leaked Redis data can't be replayed as tokens. |
| Refresh token **rotation** in one Lua script | Each refresh token works once. The script is atomic, so two concurrent refreshes can't both succeed. |
| A replayed refresh token **ends the session** | A used token coming back means two parties hold it. The server can't tell which one is the thief, so the session ends and the user logs in again. |
| Sessions end **30 days** after login (`auth.session.max-session-age`) | Without a cap, a stolen token that keeps being refreshed would work forever. |
| Role re-read on refresh | A role change takes effect within one access-token lifetime. |
| Token bucket in a **Lua script** | The read, refill and take happen in one atomic step, so 20 simultaneous requests can't take more than 5 tokens. |
| Rate limit by `remoteAddr`, not `X-Forwarded-For` | The client can spoof the header (see Limitations). |
| BCrypt check runs even for unknown emails | Response time doesn't reveal which emails are registered. |
| Same 401 for unknown email and wrong password | Prevents account enumeration. |
| GitHub email that matches a password account → 409, not auto-link | Auto-linking unverified emails can be used to take over accounts. |
| Passwords capped at 72 **bytes**, at register and login | BCrypt only uses the first 72 bytes. A character limit lets multi-byte passwords past it, which gave a 500 on register and let a longer password log in if it started with the right one. |
| `JWT_SECRET` never committed | Missing → random key (dev). Too short → the app refuses to start. |

### Limitations (known, accepted)

- **Logout leaves a short window.** After logout, the access token keeps working until it expires, at most 15 minutes. A denylist would close that window, but every request would then need a Redis call.
- **Proxies.** Behind a reverse proxy every client has the proxy's IP. To fix this, configure Spring's `ForwardedHeaderFilter` to trust only your proxy.
- **GitHub login returns JSON in the browser.** A real frontend would receive the tokens through a redirect instead.
- **Registration reveals whether an email is taken** (409). The rate limit (5 a minute per IP, separate from login's) slows enumeration down. Hiding it fully needs email verification, which this service doesn't have.
- **Emails aren't verified.** Anyone can register someone else's email, and that person then can't sign in with GitHub under it (409).
- **Retrying a refresh can log the user out.** If a client sends a refresh, loses the response and retries with the same token, the retry looks like a replay and ends the session.
- **Rate limits are per IP.** The limit is checked inside the handlers, not by matching the URL, so URL variants such as `/auth/%6cogin` can't skip it. There is no per-account limit, so an attacker with many IPs is slowed down less.

---

## Tests and CI

The tests are split into three levels. Every class is tagged with its level, so each level can run on its own.

| Level | What it checks | Needs Docker? | Classes |
|---|---|---|---|
| **Unit** (`@Tag("unit")`) | One class in isolation, with fakes or mocks. No Spring. | No | `JwtCodecTest`, `SessionServiceTest`, `AuthControllerLoginLimitTest`, `GithubLoginSuccessHandlerTest` |
| **Integration** (`@IntegrationTest`) | One component against **real** Postgres or Redis (Testcontainers) | Yes | `IdentityServiceIntegrationTest`, `RefreshTokenStoreIntegrationTest`, `RedisTokenBucketIntegrationTest` |
| **Functional** (`@FunctionalTest`) | The whole app through HTTP, the way an API client sees it | Yes | `RegisterFunctionalTest`, `LoginFunctionalTest`, `RefreshLogoutFunctionalTest`, `AdminFunctionalTest`, `RateLimitFunctionalTest`, `GithubLoginFunctionalTest` |

```bash
./mvnw test                          # everything
./mvnw test -Dgroups=unit            # fast, no Docker
./mvnw test -Dgroups=integration
./mvnw test -Dgroups=functional
```

To check a running app end to end (21 checks across every endpoint, including the 429):

```bash
./scripts/smoke-test.sh
```

Some security-critical tests worth reading:

- `JwtCodecTest` rejects expired tokens, tampered tokens, tokens signed with another key, and unsigned `alg: none` tokens.
- `RedisTokenBucketIntegrationTest` fires 20 concurrent requests and checks that exactly 5 are allowed.
- `RefreshTokenStoreIntegrationTest` has 10 threads use one refresh token at once and checks that exactly 1 succeeds. It also checks that a replayed token ends the session and that no token outlives its session.
- `RefreshLogoutFunctionalTest` checks that a used refresh token can't be replayed, and that logout revokes it.

**CI.** [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `./mvnw test` on every push and pull request. When the tests pass on `main`, it builds the [Dockerfile](Dockerfile) and publishes the image to `ghcr.io/arnavsharma2005/auth-rate-limiter`, tagged `latest` and with the commit SHA.
