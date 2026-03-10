
use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# ============================================================================
# Integration test: all PostgreSQL schema.json actions via pg_cedar
#
# Covers: SELECT, INSERT, UPDATE, DELETE, TRUNCATE, EXECUTE, USAGE (schema),
#         column-level SELECT, context-gated policies, superuser bypass,
#         namespace prefix, schema validation, diagnostics, statistics.
# ============================================================================

# --------------------------------------------------------------------------
# Cluster setup
# --------------------------------------------------------------------------
my $node = PostgreSQL::Test::Cluster->new('integration');
$node->init;
$node->append_conf(
    'postgresql.conf',
    "shared_preload_libraries = 'pg_cedar'\n"
      . "pg_cedar.log_decisions = on\n"
      . "pg_cedar.audit_enabled = on\n"
      . "pg_cedar.collect_stats = on\n");
$node->start;

$node->safe_psql('postgres', 'CREATE EXTENSION pg_cedar');

# --------------------------------------------------------------------------
# Test roles
# --------------------------------------------------------------------------
$node->safe_psql('postgres', 'CREATE ROLE alice LOGIN');
$node->safe_psql('postgres', 'CREATE ROLE bob LOGIN');

# --------------------------------------------------------------------------
# Test objects
# --------------------------------------------------------------------------
$node->safe_psql('postgres', q{
    CREATE TABLE public.items (id int, name text)
});
$node->safe_psql('postgres', q{
    INSERT INTO public.items VALUES (1, 'widget'), (2, 'gadget')
});
$node->safe_psql('postgres', q{
    CREATE FUNCTION public.get_value() RETURNS int
    LANGUAGE sql AS $$ SELECT 42 $$
});

# Revoke all default privileges — Cedar is now the sole authority
$node->safe_psql('postgres',
    'REVOKE ALL ON TABLE public.items FROM PUBLIC');
$node->safe_psql('postgres',
    'REVOKE ALL ON FUNCTION public.get_value() FROM PUBLIC');
$node->safe_psql('postgres',
    'REVOKE ALL ON SCHEMA public FROM PUBLIC');

# --------------------------------------------------------------------------
# Load Cedar policies covering all PostgreSQL schema.json actions for alice.
# Bob has no policies → default-deny applies.
# Resource UIDs match what cedar_evaluate() constructs in pg_cedar.c:
#   Table:   "schema.table"
#   Column:  "schema.table.column"
#   Schema:  "schemaname"
#   Routine: "funcname"  (get_func_name returns unqualified name)
# --------------------------------------------------------------------------
$node->safe_psql('postgres', q{
    SELECT cedar_set_policies('integration', $CEDAR$
// SELECT on Table and Column
permit(principal == User::"alice", action == Action::"SELECT",   resource == Table::"public.items");
permit(principal == User::"alice", action == Action::"SELECT",   resource == Column::"public.items.id");
// Writes
permit(principal == User::"alice", action == Action::"INSERT",   resource == Table::"public.items");
permit(principal == User::"alice", action == Action::"UPDATE",   resource == Table::"public.items");
permit(principal == User::"alice", action == Action::"DELETE",   resource == Table::"public.items");
permit(principal == User::"alice", action == Action::"TRUNCATE", resource == Table::"public.items");
// Function execution (resource is unqualified function name)
permit(principal == User::"alice", action == Action::"EXECUTE",  resource == Routine::"get_value");
// Schema access (required for any object in public schema)
permit(principal == User::"alice", action == Action::"USAGE",    resource == Schema::"public");
$CEDAR$)
});

# ============================================================================
# SECTION 1: Manual authorization checks via cedar_is_authorized()
# ============================================================================

# --- SELECT ---
my $r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"SELECT"', 'Table::"public.items"', NULL)});
is($r, 'Allow', 'Manual: alice SELECT on Table → Allow');

$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"bob"', 'Action::"SELECT"', 'Table::"public.items"', NULL)});
is($r, 'Deny', 'Manual: bob SELECT on Table → Deny');

# --- INSERT ---
$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"INSERT"', 'Table::"public.items"', NULL)});
is($r, 'Allow', 'Manual: alice INSERT on Table → Allow');

$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"bob"', 'Action::"INSERT"', 'Table::"public.items"', NULL)});
is($r, 'Deny', 'Manual: bob INSERT on Table → Deny');

# --- UPDATE ---
$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"UPDATE"', 'Table::"public.items"', NULL)});
is($r, 'Allow', 'Manual: alice UPDATE on Table → Allow');

$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"bob"', 'Action::"UPDATE"', 'Table::"public.items"', NULL)});
is($r, 'Deny', 'Manual: bob UPDATE on Table → Deny');

# --- DELETE ---
$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"DELETE"', 'Table::"public.items"', NULL)});
is($r, 'Allow', 'Manual: alice DELETE on Table → Allow');

$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"bob"', 'Action::"DELETE"', 'Table::"public.items"', NULL)});
is($r, 'Deny', 'Manual: bob DELETE on Table → Deny');

# --- TRUNCATE ---
$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"TRUNCATE"', 'Table::"public.items"', NULL)});
is($r, 'Allow', 'Manual: alice TRUNCATE on Table → Allow');

$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"bob"', 'Action::"TRUNCATE"', 'Table::"public.items"', NULL)});
is($r, 'Deny', 'Manual: bob TRUNCATE on Table → Deny');

# --- EXECUTE ---
$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"EXECUTE"', 'Routine::"get_value"', NULL)});
is($r, 'Allow', 'Manual: alice EXECUTE on Routine → Allow');

$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"bob"', 'Action::"EXECUTE"', 'Routine::"get_value"', NULL)});
is($r, 'Deny', 'Manual: bob EXECUTE on Routine → Deny');

# --- USAGE on Schema ---
$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"USAGE"', 'Schema::"public"', NULL)});
is($r, 'Allow', 'Manual: alice USAGE on Schema → Allow');

$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"bob"', 'Action::"USAGE"', 'Schema::"public"', NULL)});
is($r, 'Deny', 'Manual: bob USAGE on Schema → Deny');

# --- Column-level SELECT ---
$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"SELECT"', 'Column::"public.items.id"', NULL)});
is($r, 'Allow', 'Manual: alice column-level SELECT on id → Allow');

# alice has no policy for the "name" column → denied
$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"SELECT"', 'Column::"public.items.name"', NULL)});
is($r, 'Deny', 'Manual: alice column-level SELECT on name (no policy) → Deny');

# ============================================================================
# SECTION 2: Context-gated policies
# ============================================================================
# Add a policy that restricts ctx_user to weekdays via context.day
$node->safe_psql('postgres', q{
    SELECT cedar_set_policies('weekday', $CEDAR$
permit(principal == User::"ctx_user", action == Action::"SELECT", resource == Table::"public.items")
    when { context.day == "mon" || context.day == "tue" || context.day == "wed" ||
           context.day == "thu" || context.day == "fri" };
$CEDAR$)
});

# Weekday context → allowed
$r = $node->safe_psql('postgres', q{
    SELECT cedar_is_authorized(
        'User::"ctx_user"', 'Action::"SELECT"', 'Table::"public.items"',
        '{"day":"mon","date":20260601}')
});
is($r, 'Allow', 'Context: ctx_user SELECT on weekday (mon) → Allow');

# Weekend context → denied
$r = $node->safe_psql('postgres', q{
    SELECT cedar_is_authorized(
        'User::"ctx_user"', 'Action::"SELECT"', 'Table::"public.items"',
        '{"day":"sat","date":20260606}')
});
is($r, 'Deny', 'Context: ctx_user SELECT on weekend (sat) → Deny');

# ============================================================================
# SECTION 3: Hook-based authorization (real SQL operations)
# ============================================================================

# --- SELECT via hook ---
my ($ret, $stdout, $stderr) = $node->psql('postgres',
    'SELECT id, name FROM public.items ORDER BY id',
    extra_params => ['-U', 'alice']);
is($ret, 0, 'Hook: alice SELECT FROM items → success');

($ret, $stdout, $stderr) = $node->psql('postgres',
    'SELECT * FROM public.items',
    extra_params => ['-U', 'bob']);
isnt($ret, 0, 'Hook: bob SELECT FROM items → denied');
like($stderr, qr/permission denied/, 'Hook: bob SELECT has permission denied message');

# --- INSERT via hook ---
($ret, $stdout, $stderr) = $node->psql('postgres',
    q{INSERT INTO public.items VALUES (3, 'sprocket')},
    extra_params => ['-U', 'alice']);
is($ret, 0, 'Hook: alice INSERT INTO items → success');

($ret, $stdout, $stderr) = $node->psql('postgres',
    q{INSERT INTO public.items VALUES (99, 'intruder')},
    extra_params => ['-U', 'bob']);
isnt($ret, 0, 'Hook: bob INSERT INTO items → denied');
like($stderr, qr/permission denied/, 'Hook: bob INSERT has permission denied message');

# --- UPDATE via hook ---
($ret, $stdout, $stderr) = $node->psql('postgres',
    q{UPDATE public.items SET name = 'updated_widget' WHERE id = 1},
    extra_params => ['-U', 'alice']);
is($ret, 0, 'Hook: alice UPDATE items → success');

($ret, $stdout, $stderr) = $node->psql('postgres',
    q{UPDATE public.items SET name = 'hacked' WHERE id = 1},
    extra_params => ['-U', 'bob']);
isnt($ret, 0, 'Hook: bob UPDATE items → denied');
like($stderr, qr/permission denied/, 'Hook: bob UPDATE has permission denied message');

# --- DELETE via hook ---
($ret, $stdout, $stderr) = $node->psql('postgres',
    q{DELETE FROM public.items WHERE id = 3},
    extra_params => ['-U', 'alice']);
is($ret, 0, 'Hook: alice DELETE FROM items → success');

($ret, $stdout, $stderr) = $node->psql('postgres',
    q{DELETE FROM public.items WHERE id = 1},
    extra_params => ['-U', 'bob']);
isnt($ret, 0, 'Hook: bob DELETE FROM items → denied');
like($stderr, qr/permission denied/, 'Hook: bob DELETE has permission denied message');

# --- TRUNCATE via hook ---
($ret, $stdout, $stderr) = $node->psql('postgres',
    'TRUNCATE TABLE public.items',
    extra_params => ['-U', 'alice']);
is($ret, 0, 'Hook: alice TRUNCATE items → success');

($ret, $stdout, $stderr) = $node->psql('postgres',
    'TRUNCATE TABLE public.items',
    extra_params => ['-U', 'bob']);
isnt($ret, 0, 'Hook: bob TRUNCATE items → denied');
like($stderr, qr/permission denied/, 'Hook: bob TRUNCATE has permission denied message');

# --- EXECUTE via hook ---
($ret, $stdout, $stderr) = $node->psql('postgres',
    'SELECT public.get_value()',
    extra_params => ['-U', 'alice']);
is($ret, 0, 'Hook: alice EXECUTE get_value() → success');

($ret, $stdout, $stderr) = $node->psql('postgres',
    'SELECT public.get_value()',
    extra_params => ['-U', 'bob']);
isnt($ret, 0, 'Hook: bob EXECUTE get_value() → denied');
like($stderr, qr/permission denied/, 'Hook: bob EXECUTE has permission denied message');

# ============================================================================
# SECTION 4: Superuser bypass
# ============================================================================
# postgres (superuser) can do anything; Cedar hook skips superusers
($ret, $stdout, $stderr) = $node->psql('postgres',
    'SELECT * FROM public.items',
    extra_params => ['-U', 'postgres']);
is($ret, 0, 'Superuser: postgres SELECT without Cedar policy → success');

($ret, $stdout, $stderr) = $node->psql('postgres',
    'SELECT public.get_value()',
    extra_params => ['-U', 'postgres']);
is($ret, 0, 'Superuser: postgres EXECUTE without Cedar policy → success');

# ============================================================================
# SECTION 5: Schema validation
# ============================================================================
# Load a Cedar schema matching the PostgreSQL schema.json definition
$node->safe_psql('postgres', q{
    SELECT cedar_set_schema('pg_schema', $SCHEMA${
  "PostgreSQL": {
    "entityTypes": {
      "User":    { "shape": { "type": "Record", "attributes": {} } },
      "Table":   { "shape": { "type": "Record", "attributes": {} } },
      "Column":  { "shape": { "type": "Record", "attributes": {} } },
      "Schema":  { "shape": { "type": "Record", "attributes": {} } },
      "Routine": { "shape": { "type": "Record", "attributes": {} } }
    },
    "actions": {
      "SELECT":   { "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["Table", "Column"] } },
      "INSERT":   { "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["Table"] } },
      "UPDATE":   { "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["Table"] } },
      "DELETE":   { "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["Table"] } },
      "TRUNCATE": { "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["Table"] } },
      "EXECUTE":  { "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["Routine"] } },
      "USAGE":    { "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["Schema"] } }
    }
  }
}$SCHEMA$)
});

my $valid = $node->safe_psql('postgres', 'SELECT cedar_validate()');
is($valid, 'OK', 'Schema validation: policies match Cedar schema → OK');

# ============================================================================
# SECTION 6: cedar_explain_decision diagnostics
# ============================================================================
my $diag = $node->safe_psql('postgres',
    q{SELECT cedar_explain_decision('User::"alice"', 'Action::"SELECT"', 'Table::"public.items"', NULL)});
like($diag, qr/reasons/, 'Explain (allow): diagnostics has reasons field');
like($diag, qr/errors/,  'Explain (allow): diagnostics has errors field');

$diag = $node->safe_psql('postgres',
    q{SELECT cedar_explain_decision('User::"bob"', 'Action::"SELECT"', 'Table::"public.items"', NULL)});
like($diag, qr/reasons/, 'Explain (deny): diagnostics has reasons field (empty)');
like($diag, qr/errors/,  'Explain (deny): diagnostics has errors field');

# ============================================================================
# SECTION 7: Authorization statistics
# ============================================================================
# We have run many manual cedar_is_authorized calls; stats should be non-zero
my $grants = $node->safe_psql('postgres',
    'SELECT auth_grants > 0 FROM cedar_stats()');
is($grants, 't', 'Stats: auth_grants > 0 after allow decisions');

my $denies = $node->safe_psql('postgres',
    'SELECT auth_denies > 0 FROM cedar_stats()');
is($denies, 't', 'Stats: auth_denies > 0 after deny decisions');

# Reset stats and verify they go to zero
$node->safe_psql('postgres', 'SELECT cedar_reset_stats()');
my $zero = $node->safe_psql('postgres',
    'SELECT auth_requests FROM cedar_stats()');
is($zero, '0', 'Stats: auth_requests = 0 after cedar_reset_stats()');

# ============================================================================
# SECTION 8: Namespace prefix
# ============================================================================
# When pg_cedar.namespace is set, the hook prepends it to all Cedar UIDs.
# Manual cedar_is_authorized passes UIDs verbatim, so namespaced UIDs must
# be passed explicitly to match a namespaced policy.
my $node2 = PostgreSQL::Test::Cluster->new('namespace');
$node2->init;
$node2->append_conf(
    'postgresql.conf',
    "shared_preload_libraries = 'pg_cedar'\n"
      . "pg_cedar.namespace = 'PG'\n");
$node2->start;
$node2->safe_psql('postgres', 'CREATE EXTENSION pg_cedar');
$node2->safe_psql('postgres', 'CREATE ROLE alice LOGIN');
$node2->safe_psql('postgres', q{
    CREATE TABLE public.items (id int)
});
$node2->safe_psql('postgres',
    'REVOKE ALL ON TABLE public.items FROM PUBLIC');
$node2->safe_psql('postgres',
    'REVOKE ALL ON SCHEMA public FROM PUBLIC');

# Policy uses namespaced entity UIDs
$node2->safe_psql('postgres', q{
    SELECT cedar_set_policies('ns', $CEDAR$
permit(principal == PG::User::"alice", action == PG::Action::"SELECT", resource == PG::Table::"public.items");
permit(principal == PG::User::"alice", action == PG::Action::"USAGE",  resource == PG::Schema::"public");
$CEDAR$)
});

# Manual call: pass namespaced UIDs explicitly
my $ns_r = $node2->safe_psql('postgres',
    q{SELECT cedar_is_authorized('PG::User::"alice"', 'PG::Action::"SELECT"', 'PG::Table::"public.items"', NULL)});
is($ns_r, 'Allow', 'Namespace: manual cedar_is_authorized with PG:: prefix → Allow');

my $ns_deny = $node2->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"SELECT"', 'Table::"public.items"', NULL)});
is($ns_deny, 'Deny',
    'Namespace: manual cedar_is_authorized without prefix → Deny (policy uses prefix)');

# Hook-based: the hook adds the namespace automatically
($ret, $stdout, $stderr) = $node2->psql('postgres',
    'SELECT * FROM public.items',
    extra_params => ['-U', 'alice']);
is($ret, 0, 'Namespace: hook-based alice SELECT with PG:: namespace → success');

$node2->stop;

# ============================================================================
# SECTION 9: Cedar reload
# ============================================================================
my $reload = $node->safe_psql('postgres', 'SELECT cedar_reload()');
is($reload, 't', 'cedar_reload() returns true');

# After reload, policies are still active
$r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"SELECT"', 'Table::"public.items"', NULL)});
is($r, 'Allow', 'After reload: alice SELECT still authorized');

# ============================================================================
# SECTION 10: Audit log table exists and is accessible
# ============================================================================
my $audit_count = $node->safe_psql('postgres',
    'SELECT count(*) FROM cedar_audit_log');
# The audit log count depends on whether the implementation writes to it;
# we just verify the table is queryable (schema is correct).
ok(defined $audit_count, 'cedar_audit_log table is accessible');

# ============================================================================
# SECTION 11: cedar_config view reflects GUC settings
# ============================================================================
my $cfg_enabled = $node->safe_psql('postgres',
    q{SELECT enabled FROM cedar_config});
is($cfg_enabled, 'on', 'cedar_config: enabled = on');

my $cfg_cache = $node->safe_psql('postgres',
    q{SELECT cache_enabled FROM cedar_config});
is($cfg_cache, 'on', 'cedar_config: cache_enabled = on');

# ============================================================================
# Cleanup
# ============================================================================
$node->stop;
done_testing();
