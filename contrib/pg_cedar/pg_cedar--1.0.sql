/* contrib/pg_cedar/pg_cedar--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_cedar" to load this file. \quit

/* ========================================================================
 * Catalog tables
 * ======================================================================== */

-- Named Cedar policysets
CREATE TABLE cedar_policies (
    id          serial      PRIMARY KEY,
    name        text        NOT NULL UNIQUE,
    policy_text text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    is_active   boolean     NOT NULL DEFAULT true
);

COMMENT ON TABLE cedar_policies IS
'Stores named Cedar policysets.  Active rows are loaded into the engine.';

-- Cedar schemas (JSON)
CREATE TABLE cedar_schemas (
    id          serial      PRIMARY KEY,
    name        text        NOT NULL UNIQUE,
    schema_json text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    is_active   boolean     NOT NULL DEFAULT true
);

COMMENT ON TABLE cedar_schemas IS
'Stores Cedar schemas for request/entity validation.';

-- Entity snapshots (JSON)
CREATE TABLE cedar_entities (
    id            serial      PRIMARY KEY,
    entities_json text        NOT NULL,
    description   text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    is_active     boolean     NOT NULL DEFAULT true
);

COMMENT ON TABLE cedar_entities IS
'Stores Cedar entity snapshots (Cedar entity JSON format).';

-- Audit log
CREATE TABLE cedar_audit_log (
    id           bigserial   PRIMARY KEY,
    ts           timestamptz NOT NULL DEFAULT now(),
    principal    text,
    action       text,
    resource     text,
    decision     text,
    diagnostics  text,
    policy_name  text
);

COMMENT ON TABLE cedar_audit_log IS
'Audit trail of Cedar authorization decisions.';

/* ========================================================================
 * SQL-callable functions (C implementations)
 * ======================================================================== */

-- Check if the extension is enabled
CREATE FUNCTION cedar_is_enabled()
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_cedar_is_enabled'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_is_enabled() IS
'Returns true if the pg_cedar authorization engine is enabled.';

-- Upsert a named policyset
CREATE FUNCTION cedar_set_policies(policy_name text, policy_text text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_cedar_set_policies'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_set_policies(text, text) IS
'Insert or update a named Cedar policyset in the catalog and reload the engine.
Example: SELECT cedar_set_policies(''default'', ''permit(principal, action, resource);'');';

-- Upsert a named schema
CREATE FUNCTION cedar_set_schema(schema_name text, schema_json text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_cedar_set_schema'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_set_schema(text, text) IS
'Insert or update a named Cedar schema in the catalog and reload the engine.';

-- Set entities
CREATE FUNCTION cedar_set_entities(entities_json text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_cedar_set_entities'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_set_entities(text) IS
'Replace the entity store with the given Cedar entity JSON and reload the engine.';

-- Manual authorization check
CREATE FUNCTION cedar_is_authorized(
    principal text,
    action text,
    resource text,
    context_json text DEFAULT NULL
)
RETURNS text
AS 'MODULE_PATHNAME', 'pg_cedar_is_authorized'
LANGUAGE C VOLATILE;

COMMENT ON FUNCTION cedar_is_authorized(text, text, text, text) IS
'Evaluate a Cedar authorization request.  Returns ''Allow'', ''Deny'', or ''Error''.
Example: SELECT cedar_is_authorized(''User::"alice"'', ''Action::"SELECT"'', ''Table::"public.t"'', NULL);';

-- Validate policies against loaded schema
CREATE FUNCTION cedar_validate()
RETURNS text
AS 'MODULE_PATHNAME', 'pg_cedar_validate'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_validate() IS
'Validate the active policies against the active schema. Returns ''OK'' or error message.';

-- Explain a decision (returns diagnostics JSON)
CREATE FUNCTION cedar_explain_decision(
    principal text,
    action text,
    resource text,
    context_json text DEFAULT NULL
)
RETURNS text
AS 'MODULE_PATHNAME', 'pg_cedar_explain_decision'
LANGUAGE C VOLATILE;

COMMENT ON FUNCTION cedar_explain_decision(text, text, text, text) IS
'Evaluate an authorization request and return JSON diagnostics (reasons + errors).';

-- Reload policies/schema/entities from catalog into the engine
CREATE FUNCTION cedar_reload()
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_cedar_reload'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_reload() IS
'Reload all active policies, schemas, and entities from catalog tables into the Cedar engine.';

-- Authorization statistics
CREATE FUNCTION cedar_stats(
    OUT auth_requests bigint,
    OUT auth_grants bigint,
    OUT auth_denies bigint,
    OUT auth_ignores bigint,
    OUT auth_errors bigint,
    OUT eval_time_us double precision
)
RETURNS record
AS 'MODULE_PATHNAME', 'pg_cedar_stats'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_stats() IS
'Returns authorization statistics.';

-- Reset statistics
CREATE FUNCTION cedar_reset_stats()
RETURNS void
AS 'MODULE_PATHNAME', 'pg_cedar_reset_stats'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_reset_stats() IS
'Reset all authorization statistics to zero.';

-- Cache statistics
CREATE FUNCTION cedar_cache_stats(
    OUT hits bigint,
    OUT misses bigint,
    OUT evictions bigint,
    OUT entries bigint
)
RETURNS record
AS 'MODULE_PATHNAME', 'pg_cedar_cache_stats'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_cache_stats() IS
'Returns authorization cache hit/miss/eviction statistics.';

-- Reset cache
CREATE FUNCTION cedar_cache_reset()
RETURNS void
AS 'MODULE_PATHNAME', 'pg_cedar_cache_reset'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_cache_reset() IS
'Flush the authorization decision cache.';

/* ========================================================================
 * Convenience views
 * ======================================================================== */

CREATE VIEW cedar_statistics AS
SELECT * FROM cedar_stats();

COMMENT ON VIEW cedar_statistics IS
'View showing current Cedar authorization statistics.';

CREATE VIEW cedar_config AS
SELECT
    current_setting('pg_cedar.enabled', true) AS enabled,
    current_setting('pg_cedar.namespace', true) AS cedar_namespace,
    current_setting('pg_cedar.log_decisions', true) AS log_decisions,
    current_setting('pg_cedar.audit_enabled', true) AS audit_enabled,
    current_setting('pg_cedar.cache_enabled', true) AS cache_enabled,
    current_setting('pg_cedar.cache_size', true) AS cache_size,
    current_setting('pg_cedar.cache_ttl', true) AS cache_ttl;

COMMENT ON VIEW cedar_config IS
'View showing current pg_cedar configuration.';
