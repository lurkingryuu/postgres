/* contrib/pg_cedar/pg_cedar--1.1.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_cedar" to load this file. \quit

/* ========================================================================
 * Catalog tables
 * ======================================================================== */

-- Named Cedar policysets (with full lifecycle columns)
CREATE TABLE cedar_policies (
    id             serial      PRIMARY KEY,
    name           text        NOT NULL UNIQUE,
    policy_text    text        NOT NULL,
    policy_hash    text,
    status         text        NOT NULL DEFAULT 'active'
        CHECK (status IN ('draft', 'staged', 'shadow', 'active', 'archived')),
    version        integer     NOT NULL DEFAULT 1,
    prev_active_id integer     REFERENCES cedar_policies(id),
    activated_by   text,
    activated_at   timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    is_active      boolean     NOT NULL DEFAULT true
);

COMMENT ON TABLE cedar_policies IS
'Named Cedar policysets with full lifecycle (draft → staged → active → archived).';

-- Cedar schemas (JSON)
CREATE TABLE cedar_schemas (
    id          serial      PRIMARY KEY,
    name        text        NOT NULL UNIQUE,
    schema_json text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    is_active   boolean     NOT NULL DEFAULT true
);

COMMENT ON TABLE cedar_schemas IS
'Cedar schemas for request/entity validation.';

-- Entity snapshots (JSON)
CREATE TABLE cedar_entities (
    id            serial      PRIMARY KEY,
    entities_json text        NOT NULL,
    description   text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    is_active     boolean     NOT NULL DEFAULT true
);

COMMENT ON TABLE cedar_entities IS
'Cedar entity snapshots (Cedar entity JSON format).';

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

-- Attribute registry
CREATE TABLE cedar_attributes (
    id          serial      PRIMARY KEY,
    name        text        NOT NULL UNIQUE,
    attr_type   text        NOT NULL DEFAULT 'text',
    applies_to  text        NOT NULL DEFAULT 'both'
        CHECK (applies_to IN ('principal', 'resource', 'both')),
    created_at  timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE cedar_attributes IS
'Registry of ABAC attribute definitions.';

-- Principal attribute store
CREATE TABLE cedar_principal_attrs (
    id          serial      PRIMARY KEY,
    principal   text        NOT NULL,
    attr_name   text        NOT NULL,
    attr_value  text        NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (principal, attr_name)
);

COMMENT ON TABLE cedar_principal_attrs IS
'Per-principal ABAC attribute assignments.';

/* ========================================================================
 * SQL-callable functions (C implementations)
 * ======================================================================== */

CREATE FUNCTION cedar_is_enabled()
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_cedar_is_enabled'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_is_enabled() IS
'Returns true if the pg_cedar authorization engine is enabled.';

CREATE FUNCTION cedar_set_policies(policy_name text, policy_text text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_cedar_set_policies'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_set_policies(text, text) IS
'Insert or update a named Cedar policyset in the catalog and reload the engine.';

CREATE FUNCTION cedar_set_schema(schema_name text, schema_json text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_cedar_set_schema'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_set_schema(text, text) IS
'Insert or update a named Cedar schema in the catalog and reload the engine.';

CREATE FUNCTION cedar_set_entities(entities_json text)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_cedar_set_entities'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_set_entities(text) IS
'Replace the entity store with the given Cedar entity JSON and reload the engine.';

CREATE FUNCTION cedar_is_authorized(
    principal    text,
    action       text,
    resource     text,
    context_json text DEFAULT NULL
)
RETURNS text
AS 'MODULE_PATHNAME', 'pg_cedar_is_authorized'
LANGUAGE C VOLATILE;

COMMENT ON FUNCTION cedar_is_authorized(text, text, text, text) IS
'Evaluate a Cedar authorization request. Returns ''Allow'', ''Deny'', or ''Error''.';

CREATE FUNCTION cedar_validate()
RETURNS text
AS 'MODULE_PATHNAME', 'pg_cedar_validate'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_validate() IS
'Validate the active policies against the active schema.';

CREATE FUNCTION cedar_validate_text(
    policy_text text,
    schema_json text DEFAULT NULL
)
RETURNS text
AS 'MODULE_PATHNAME', 'pg_cedar_validate_text'
LANGUAGE C VOLATILE;

COMMENT ON FUNCTION cedar_validate_text(text, text) IS
'Validate Cedar policy text against an optional schema using a throw-away engine.
Safe to call on staged/draft policies — never affects the live engine.';

CREATE FUNCTION cedar_explain_decision(
    principal    text,
    action       text,
    resource     text,
    context_json text DEFAULT NULL
)
RETURNS text
AS 'MODULE_PATHNAME', 'pg_cedar_explain_decision'
LANGUAGE C VOLATILE;

COMMENT ON FUNCTION cedar_explain_decision(text, text, text, text) IS
'Evaluate an authorization request and return JSON diagnostics.';

CREATE FUNCTION cedar_reload()
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_cedar_reload'
LANGUAGE C STRICT VOLATILE;

COMMENT ON FUNCTION cedar_reload() IS
'Reload all active policies, schemas, and entities from catalog tables.';

CREATE FUNCTION cedar_stats(
    OUT auth_requests  bigint,
    OUT auth_grants    bigint,
    OUT auth_denies    bigint,
    OUT auth_ignores   bigint,
    OUT auth_errors    bigint,
    OUT eval_time_us   double precision
)
RETURNS record
AS 'MODULE_PATHNAME', 'pg_cedar_stats'
LANGUAGE C STRICT VOLATILE;

CREATE FUNCTION cedar_reset_stats()
RETURNS void
AS 'MODULE_PATHNAME', 'pg_cedar_reset_stats'
LANGUAGE C STRICT VOLATILE;

CREATE FUNCTION cedar_cache_stats(
    OUT hits       bigint,
    OUT misses     bigint,
    OUT evictions  bigint,
    OUT entries    bigint
)
RETURNS record
AS 'MODULE_PATHNAME', 'pg_cedar_cache_stats'
LANGUAGE C STRICT VOLATILE;

CREATE FUNCTION cedar_cache_reset()
RETURNS void
AS 'MODULE_PATHNAME', 'pg_cedar_cache_reset'
LANGUAGE C STRICT VOLATILE;

/* ========================================================================
 * ABAC governance functions
 * ======================================================================== */

CREATE FUNCTION abac_stage_policyset(p_name text, p_policy_text text)
RETURNS text
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    v_hash      text    := md5(p_policy_text);
    v_existing  record;
BEGIN
    SELECT id, version INTO v_existing
      FROM cedar_policies WHERE name = p_name;

    IF NOT FOUND THEN
        INSERT INTO cedar_policies
               (name, policy_text, policy_hash, status, version, is_active)
        VALUES (p_name, p_policy_text, v_hash, 'staged', 1, false);
        RETURN 'staged: new policyset ' || quote_literal(p_name) || ' v1';
    ELSE
        UPDATE cedar_policies
           SET policy_text  = p_policy_text,
               policy_hash  = v_hash,
               status       = 'staged',
               version      = v_existing.version + 1,
               is_active    = false,
               created_at   = now()
         WHERE id = v_existing.id;
        RETURN 'staged: ' || quote_literal(p_name)
               || ' v' || (v_existing.version + 1);
    END IF;
END;
$$;

COMMENT ON FUNCTION abac_stage_policyset(text, text) IS
'Stage a policy for review. Does NOT activate — use abac_activate_policyset() to go live.';

CREATE FUNCTION abac_validate_policyset(p_name text)
RETURNS text
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    v_policy_text   text;
    v_schema_json   text;
BEGIN
    SELECT policy_text INTO v_policy_text
      FROM cedar_policies WHERE name = p_name;

    IF NOT FOUND THEN
        RETURN 'Error: policyset not found: ' || quote_literal(p_name);
    END IF;

    SELECT schema_json INTO v_schema_json
      FROM cedar_schemas
     WHERE is_active = true
     ORDER BY id DESC
     LIMIT 1;

    RETURN cedar_validate_text(v_policy_text, v_schema_json);
END;
$$;

COMMENT ON FUNCTION abac_validate_policyset(text) IS
'Validate a named policy against the active schema using a throw-away engine.';

CREATE FUNCTION abac_activate_policyset(p_name text)
RETURNS text
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    v_rec       record;
    v_prev_id   integer;
BEGIN
    SELECT id, version, status INTO v_rec
      FROM cedar_policies
     WHERE name = p_name
       AND status NOT IN ('active', 'archived')
     ORDER BY version DESC
     LIMIT 1;

    IF NOT FOUND THEN
        SELECT id, version INTO v_rec
          FROM cedar_policies
         WHERE name = p_name AND status = 'active'
         ORDER BY version DESC LIMIT 1;

        IF NOT FOUND THEN
            RETURN 'Error: no policy found: ' || quote_literal(p_name);
        END IF;
        RETURN 'already active: ' || quote_literal(p_name) || ' v' || v_rec.version;
    END IF;

    SELECT id INTO v_prev_id
      FROM cedar_policies
     WHERE name = p_name AND status = 'active'
     ORDER BY version DESC LIMIT 1;

    UPDATE cedar_policies
       SET status    = 'archived',
           is_active = false
     WHERE name = p_name AND status IN ('active', 'shadow');

    UPDATE cedar_policies
       SET status         = 'active',
           is_active      = true,
           prev_active_id = v_prev_id,
           activated_by   = current_user,
           activated_at   = now()
     WHERE id = v_rec.id;

    PERFORM cedar_reload();

    RETURN 'activated: ' || quote_literal(p_name) || ' v' || v_rec.version;
END;
$$;

COMMENT ON FUNCTION abac_activate_policyset(text) IS
'Atomically promote a staged policy to active. Archives the previous version and reloads the engine.';

CREATE FUNCTION abac_rollback_policyset(p_name text)
RETURNS text
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    v_current   record;
    v_prev      record;
BEGIN
    SELECT id, version, prev_active_id INTO v_current
      FROM cedar_policies
     WHERE name = p_name AND status = 'active'
     ORDER BY version DESC LIMIT 1;

    IF NOT FOUND THEN
        RETURN 'Error: no active policy to rollback: ' || quote_literal(p_name);
    END IF;

    IF v_current.prev_active_id IS NULL THEN
        RETURN 'Error: no previous version recorded for ' || quote_literal(p_name);
    END IF;

    SELECT id, version INTO v_prev
      FROM cedar_policies WHERE id = v_current.prev_active_id;

    IF NOT FOUND THEN
        RETURN 'Error: previous version record missing (id=' || v_current.prev_active_id || ')';
    END IF;

    UPDATE cedar_policies
       SET status    = 'archived',
           is_active = false
     WHERE id = v_current.id;

    UPDATE cedar_policies
       SET status       = 'active',
           is_active    = true,
           activated_by = current_user,
           activated_at = now()
     WHERE id = v_prev.id;

    PERFORM cedar_reload();

    RETURN 'rolled back: ' || quote_literal(p_name)
           || ' from v' || v_current.version
           || ' to v' || v_prev.version;
END;
$$;

COMMENT ON FUNCTION abac_rollback_policyset(text) IS
'Roll back the named policy to its previous active version.';

CREATE FUNCTION abac_shadow_policyset(p_name text)
RETURNS text
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
    v_rec record;
BEGIN
    SELECT id INTO v_rec FROM cedar_policies WHERE name = p_name;

    IF NOT FOUND THEN
        RETURN 'Error: policyset not found: ' || quote_literal(p_name);
    END IF;

    UPDATE cedar_policies
       SET status    = 'shadow',
           is_active = false
     WHERE id = v_rec.id;

    RETURN 'shadow mode enabled: ' || quote_literal(p_name);
END;
$$;

COMMENT ON FUNCTION abac_shadow_policyset(text) IS
'Put a policy into shadow mode — evaluated and audited but not enforced.';

CREATE FUNCTION abac_effective_policies(
    OUT name         text,
    OUT version      integer,
    OUT policy_hash  text,
    OUT activated_by text,
    OUT activated_at timestamptz
)
RETURNS SETOF record
LANGUAGE sql STABLE AS $$
    SELECT name, version, policy_hash, activated_by, activated_at
      FROM cedar_policies
     WHERE status = 'active'
     ORDER BY name;
$$;

COMMENT ON FUNCTION abac_effective_policies() IS
'List currently active policysets.';

CREATE FUNCTION abac_explain_decision(
    principal    text,
    action       text,
    resource     text,
    context_json text DEFAULT NULL
)
RETURNS text
LANGUAGE sql VOLATILE AS $$
    SELECT cedar_explain_decision(principal, action, resource, context_json);
$$;

COMMENT ON FUNCTION abac_explain_decision(text, text, text, text) IS
'Explain a Cedar authorization decision.';

CREATE FUNCTION abac_create_attribute(
    p_name       text,
    p_type       text DEFAULT 'text',
    p_applies_to text DEFAULT 'both'
)
RETURNS text
LANGUAGE plpgsql VOLATILE AS $$
BEGIN
    INSERT INTO cedar_attributes (name, attr_type, applies_to)
    VALUES (p_name, p_type, p_applies_to)
    ON CONFLICT (name) DO UPDATE
       SET attr_type  = EXCLUDED.attr_type,
           applies_to = EXCLUDED.applies_to;

    RETURN 'attribute defined: ' || p_name
           || ' (' || p_type || ', applies_to=' || p_applies_to || ')';
END;
$$;

COMMENT ON FUNCTION abac_create_attribute(text, text, text) IS
'Define or update an ABAC attribute in the registry.';

CREATE FUNCTION abac_set_principal_attr(
    p_principal text,
    p_attr      text,
    p_value     text
)
RETURNS text
LANGUAGE plpgsql VOLATILE AS $$
BEGIN
    INSERT INTO cedar_principal_attrs (principal, attr_name, attr_value)
    VALUES (p_principal, p_attr, p_value)
    ON CONFLICT (principal, attr_name) DO UPDATE
       SET attr_value = EXCLUDED.attr_value,
           updated_at = now();

    RETURN 'set ' || p_principal || '.' || p_attr || ' = ' || p_value;
END;
$$;

COMMENT ON FUNCTION abac_set_principal_attr(text, text, text) IS
'Set or update a principal attribute value.';

CREATE FUNCTION abac_get_principal_attrs(
    p_principal text,
    OUT attr_name  text,
    OUT attr_value text,
    OUT updated_at timestamptz
)
RETURNS SETOF record
LANGUAGE sql STABLE AS $$
    SELECT attr_name, attr_value, updated_at
      FROM cedar_principal_attrs
     WHERE principal = p_principal
     ORDER BY attr_name;
$$;

COMMENT ON FUNCTION abac_get_principal_attrs(text) IS
'Return all attribute assignments for a principal.';

/* ========================================================================
 * Views
 * ======================================================================== */

CREATE VIEW cedar_statistics AS
SELECT * FROM cedar_stats();

COMMENT ON VIEW cedar_statistics IS
'Current Cedar authorization statistics.';

CREATE VIEW cedar_config AS
SELECT
    current_setting('pg_cedar.enabled',       true) AS enabled,
    current_setting('pg_cedar.namespace',     true) AS cedar_namespace,
    current_setting('pg_cedar.log_decisions', true) AS log_decisions,
    current_setting('pg_cedar.audit_enabled', true) AS audit_enabled,
    current_setting('pg_cedar.cache_enabled', true) AS cache_enabled,
    current_setting('pg_cedar.cache_size',    true) AS cache_size,
    current_setting('pg_cedar.cache_ttl',     true) AS cache_ttl;

COMMENT ON VIEW cedar_config IS
'Current pg_cedar configuration settings.';

CREATE VIEW cedar_policy_versions AS
SELECT
    name,
    version,
    status,
    policy_hash,
    is_active,
    activated_by,
    activated_at,
    created_at,
    left(policy_text, 120) AS policy_preview
FROM cedar_policies
ORDER BY name, version;

COMMENT ON VIEW cedar_policy_versions IS
'Full lifecycle history for all policysets.';

CREATE VIEW cedar_active_policies AS
SELECT name, version, policy_hash, activated_by, activated_at, policy_text
  FROM cedar_policies
 WHERE status = 'active'
 ORDER BY name;

COMMENT ON VIEW cedar_active_policies IS
'Currently active policysets only.';
