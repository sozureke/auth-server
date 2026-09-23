ALTER TABLE users
    ADD COLUMN mfa_enabled            BOOLEAN      NOT NULL DEFAULT FALSE,
    ADD COLUMN totp_secret            VARCHAR(255),
    ADD COLUMN mfa_last_used_interval BIGINT       NOT NULL DEFAULT 0;
