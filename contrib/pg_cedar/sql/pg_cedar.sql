/* Test the pg_cedar extension */
CREATE EXTENSION pg_cedar;

-- Check if enabled (should be true by default)
SELECT cedar_is_enabled();

-- Load a simple policy via cedar_set_policies
SELECT cedar_set_policies('test_policy',
    'permit(principal == User::"alice", action == Action::"SELECT", resource == Table::"public.test");');

-- Test manual authorization: alice should be allowed
SELECT cedar_is_authorized(
    'User::"alice"',
    'Action::"SELECT"',
    'Table::"public.test"',
    NULL
);

-- Test manual authorization: bob should be denied
SELECT cedar_is_authorized(
    'User::"bob"',
    'Action::"SELECT"',
    'Table::"public.test"',
    NULL
);

-- Validate policies (no schema loaded, should return OK)
SELECT cedar_validate();

-- Get diagnostics for alice's decision
SELECT cedar_explain_decision(
    'User::"alice"',
    'Action::"SELECT"',
    'Table::"public.test"',
    NULL
);

-- Check statistics
SELECT * FROM cedar_statistics;

-- Check cache stats
SELECT (cedar_cache_stats()).hits >= 0 AS cache_ok;

-- Reset stats
SELECT cedar_reset_stats();

-- Check configuration view
SELECT * FROM cedar_config;

-- Reload engine
SELECT cedar_reload();

-- Clean up
DROP EXTENSION pg_cedar;
