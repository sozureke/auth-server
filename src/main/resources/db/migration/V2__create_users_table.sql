CREATE TABLE users (
    id                      BIGSERIAL PRIMARY KEY,
    email                   VARCHAR(255) NOT NULL UNIQUE,
    password_hash           VARCHAR(255) NOT NULL,
    email_verified          BOOLEAN NOT NULL DEFAULT FALSE,
    verification_token      VARCHAR(255),
    failed_login_attempts   INT NOT NULL DEFAULT 0,
    locked_until            TIMESTAMP,
    enabled                 BOOLEAN NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMP NOT NULL DEFAULT now(),
    updated_at              TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_email ON users (email);