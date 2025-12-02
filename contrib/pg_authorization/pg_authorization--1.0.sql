/* contrib/pg_authorization/pg_authorization--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_authorization" to load this file. \quit

-- The pg_authorization extension is primarily a shared library that must be
-- loaded via shared_preload_libraries. This SQL file provides helper functions
-- and views for monitoring and configuration.

-- Function to check if the authorization plugin is active
CREATE FUNCTION pg_authorization_is_enabled()
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_authorization_is_enabled'
LANGUAGE C STRICT;

COMMENT ON FUNCTION pg_authorization_is_enabled()
IS 'Returns true if the pg_authorization plugin is currently enabled';

-- View showing current authorization configuration
CREATE VIEW pg_authorization_config AS
SELECT
    current_setting('pg_authorization.url', true) AS authorization_url,
    current_setting('pg_authorization.timeout', true)::integer AS timeout_ms,
    current_setting('pg_authorization.enabled', true)::boolean AS enabled,
    current_setting('pg_authorization.log_decisions', true)::boolean AS log_decisions;

COMMENT ON VIEW pg_authorization_config
IS 'Shows current pg_authorization configuration settings';

-- Grant access to monitoring view
GRANT SELECT ON pg_authorization_config TO PUBLIC;

