-- Run as: psql -U audit_admin -d authdb -v retention_days=90 -f scripts/audit-retention-cleanup.sql
-- audit_admin only has DELETE on audit_log (see V8 migration) - this cannot run as the app's
-- own role (authuser), by design.

\if :{?retention_days}
\else
  \set retention_days 90
\endif

DELETE FROM audit_log
WHERE created_at < now() - (:retention_days * interval '1 day');
