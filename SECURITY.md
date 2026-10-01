# Security

This document explains the security decisions in auth-server and, just as importantly, what it
does not protect against yet. It is a portfolio project.

## Design decisions

### Credentials and accounts

- Passwords are hashed with BCrypt, cost 12. The policy requires 12+ characters with lower and
  upper case, a digit and a special character.
- Five wrong passwords lock the account for 15 minutes. The counter is shared by every login path:
  the JSON login check, the OAuth login form, HTTP Basic and password change. The counter is
  written outside the failing request's transaction rollback, and an integration test on a real
  database checks that it sticks.
- Unknown emails and wrong passwords produce the same login response, and password reset
  requests always return 200. This does not fully prevent account discovery; see the limitations.
- Verification, reset and client secrets are random UUIDs; OAuth client secrets and MFA backup
  codes are stored as BCrypt hashes and shown once.
- Accounts must verify their email before they can sign in. Disabled accounts cannot sign in, and
  disabling or deleting an account ends its sessions.

### OAuth 2.0 and OIDC

Built on Spring Authorization Server rather than hand-written token handling.

- Only the authorization code flow, with PKCE required for every client, and refresh tokens.
  Clients are confidential (`client_secret_basic`).
- Redirect URIs must match a registered URI exactly; an unknown URI gets a 400 and is never
  redirected to, so codes cannot leak to an attacker's host.
- Access tokens are RS256 JWTs valid for 15 minutes. Refresh tokens are valid 7 days and rotate on
  every use; reusing an old one fails.
- Authorization codes are single-use and bound to the client, the redirect URI and the PKCE
  verifier.
- The end-to-end tests attack the flow directly: code reuse, a wrong verifier, a code redeemed by
  another client, a missing PKCE challenge, a foreign redirect URI, a tampered payload, an
  `alg: none` token and a token signed with a foreign key.

### Multi-factor authentication

- TOTP (RFC 6238, 30 s steps, 6 digits). The current and previous step are accepted, and a code
  from a step that was already used is rejected, so an observed code cannot be replayed.
- TOTP secrets are encrypted at rest with AES-256-GCM. The key comes from `MFA_ENCRYPTION_KEY` and
  must decode to exactly 32 bytes, otherwise the server does not start.
- Ten single-use backup codes, BCrypt-hashed. Consuming one is an atomic conditional update, so
  the same code cannot be used twice in parallel.
- Every account that enrolled MFA must pass TOTP (or a backup code) before `/oauth2/authorize`
  issues it a code. For administrators MFA is mandatory: an administrator who never enrolled is
  refused. Enrollment applies from the next sign-in. See the limitations for what this does not
  cover.

### Authorization

- Roles map to permissions; both end up as authorities and in the access token (`roles`,
  `permissions`), so resource servers can authorize without calling back.
- Admin endpoints are protected twice: a URL rule requires some admin authority on every
  `/api/admin/**` request before the body is read, and each method checks its exact permission.
  A test walks every `/api/**` endpoint registered in the application and expects 401 for
  anonymous and 403 for an unprivileged user, so a new endpoint without protection fails the
  build.
- Administrators cannot disable or delete their own account.
- Sorting is restricted to an allow-list of columns, so no response can be ordered by a secret.

### Sessions, cookies, CSRF and CORS

- Browser sessions are stored in Redis and time out after 15 minutes of inactivity. The session
  id changes on login.
- The session cookie is `HttpOnly` and `SameSite=Lax`, plus `Secure` in the prod profile. Lax,
  not Strict, because the OAuth flow returns to the server through a cross-site redirect.
- CSRF protection is on for everything that authenticates with the session cookie. The stateless
  API uses no cookies, so it has no CSRF exposure; the token endpoint authenticates the client
  with credentials.
- Session ids never leave the server: users and admins see SHA-256 hashes.
- CORS is closed unless origins are configured. A wildcard origin together with credentials is
  rejected at startup.

### Abuse protection

- A Redis sliding-window limiter (one atomic Lua script, Redis server time) protects login,
  registration, token and API endpoints. It runs before Spring Security, so rejected requests
  are counted too.
- If Redis is unavailable, login and the token endpoint fail closed (503) and registration and
  the API fail open. Brute-force protection matters more than availability on the first two.
- The token endpoint is limited per client and IP, so anyone who knows a public client id cannot
  exhaust that client's quota.
- `X-Forwarded-For` is honoured only from addresses in `TRUSTED_PROXIES`; otherwise a caller
  could spoof its address to escape the per-IP limits or to forge audit entries.

### Audit log

- Logins, failures, logouts, registrations, password and MFA changes, token issuance and
  revocation, and every administrative action are recorded with actor, IP and user agent.
- Audit writes run in their own transaction, so a failed login is recorded even though the
  request itself rolls back.
- The table is append-only for the application: UPDATE, DELETE and TRUNCATE are revoked from its
  database role. Retention cleanup runs as a separate `audit_admin` role
  (`scripts/audit-retention-cleanup.sql`).

### Data handling and operations

- Input reaches the database only through JPA parameters. Tests send SQL injection payloads
  through search, filters, sorting, path variables and login.
- Responses never include password hashes, TOTP secrets, reset or verification tokens, or client
  secrets outside the one-time creation and rotation responses.
- In the prod profile, a Logback converter masks passwords, tokens, secrets, `Basic`/`Bearer`
  credentials and JWTs in every log message, and the default error response includes no stack
  trace or exception details. API errors carry only messages written for the client. Links
  containing tokens are logged at DEBUG only.
- Secrets come from environment variables; none are in the configuration files.
- The container runs as a non-root user.

## Known limitations

These are deliberate gaps or not yet done, listed so nobody relies on protection that does not
exist.

- **MFA scope.** MFA is enforced at `/oauth2/authorize` only. HTTP Basic calls to the API are
  password-only for everyone, including administrators and users who enrolled MFA.
- **HTTP Basic on the API.** The JSON API authenticates with the account password on every
  request. Moving it to Bearer access tokens is the planned fix for this and for the MFA gap.
- **In-memory authorization state.** Issued codes, refresh tokens and revocations live in memory:
  a restart signs everybody out of their OAuth sessions, and the server cannot run as more than
  one instance.
- **Signing key.** The RSA key is generated at startup, so a restart invalidates every issued
  token. A persistent or externally managed key is needed before production use.
- **Revocation reach.** Disabling a user, revoking or refreshing a token is visible to
  `/oauth2/introspect` and `/userinfo` immediately. A resource server that only verifies the JWT
  signature keeps accepting an access token until it expires, at most 15 minutes.
- **Account discovery.** Login and password change take the same time for unknown and existing
  emails (an unknown email is still checked against a password hash computed at startup; a test
  guards this). Other paths still reveal whether an account exists: registration answers 409 for
  a registered email, a locked account answers 423 where an unknown email keeps answering 401, and
  a password reset request for an existing account performs a database write (a few milliseconds).
  The rate limits slow discovery down but do not prevent it. Closing the registration path needs
  email delivery, so that registration can always answer the same way.
- **Lockout as denial of service.** Anyone who knows an email address can lock that account for
  15 minutes with five wrong passwords. This is the usual trade-off of account lockout.
- **`PUT /auth/password`** is public (email plus current password) and not rate limited. The
  lockout covers it, but it should require authentication.
- **Fail-closed login.** A Redis outage makes login and token issuance unavailable.
- **Audit immutability depends on the database role.** The REVOKE has no effect on a superuser.
  The bundled docker-compose creates the application user as the PostgreSQL superuser, so the
  log is only append-only when the application connects with a dedicated, non-superuser role.
  CI and the Testcontainers database use a superuser too, so no test verifies the REVOKE
  behaviourally; it was checked manually against a non-superuser role.
- **No email delivery.** Verification and reset links are only written to the log in the dev
  profile.
- **Log masking** covers log messages, not exception stack traces.
- **No admin bootstrap.** The first administrator is promoted directly in the database.
