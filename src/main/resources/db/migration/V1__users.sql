CREATE TABLE users (
    id            UUID PRIMARY KEY,
    email         TEXT UNIQUE,                      -- null for GitHub users who hide their email
    password_hash TEXT,                             -- null for GitHub-only users
    github_id     BIGINT UNIQUE,                    -- null for password-only users
    role          TEXT NOT NULL DEFAULT 'USER' CHECK (role IN ('USER', 'ADMIN')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_has_login_method CHECK (password_hash IS NOT NULL OR github_id IS NOT NULL)
);
