CREATE TABLE oauth_clients (
    id                  VARCHAR(36) PRIMARY KEY,
    client_id           VARCHAR(255) NOT NULL UNIQUE,
    client_secret       VARCHAR(255) NOT NULL,
    client_name         VARCHAR(255) NOT NULL,
    require_proof_key   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMP NOT NULL DEFAULT now(),
    updated_at          TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE oauth_client_redirect_uris (
    client_id    VARCHAR(36) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    redirect_uri VARCHAR(500) NOT NULL,
    PRIMARY KEY (client_id, redirect_uri)
);

CREATE TABLE oauth_client_scopes (
    client_id VARCHAR(36) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scope     VARCHAR(100) NOT NULL,
    PRIMARY KEY (client_id, scope)
);

CREATE TABLE oauth_client_grant_types (
    client_id  VARCHAR(36) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    grant_type VARCHAR(100) NOT NULL,
    PRIMARY KEY (client_id, grant_type)
);

CREATE TABLE oauth_client_auth_methods (
    client_id   VARCHAR(36) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    auth_method VARCHAR(100) NOT NULL,
    PRIMARY KEY (client_id, auth_method)
);
