CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    entity_type VARCHAR(50),
    entity_id VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    details JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);

INSERT INTO permissions (name) VALUES ('AUDIT_READ');
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r CROSS JOIN permissions p
WHERE p.name = 'AUDIT_READ' AND r.name IN ('ADMIN', 'AUDITOR');

REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM authuser;

CREATE ROLE audit_admin;
GRANT DELETE ON audit_log TO audit_admin;
