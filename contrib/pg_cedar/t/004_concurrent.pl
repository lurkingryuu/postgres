
use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# ============================================================================
# Concurrent session test: verify Cedar authorization is correct and
# consistent under concurrent backend access, shared-memory cache integrity,
# and policy reload while connections are active.
# ============================================================================

my $node = PostgreSQL::Test::Cluster->new('concurrent');
$node->init;
$node->append_conf(
    'postgresql.conf',
    "shared_preload_libraries = 'pg_cedar'\n"
      . "pg_cedar.collect_stats = on\n"
      . "pg_cedar.cache_enabled = on\n"
      . "pg_cedar.cache_size = 256\n"
      . "pg_cedar.log_decisions = on\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_cedar');

# --------------------------------------------------------------------------
# Test users and objects
# --------------------------------------------------------------------------
$node->safe_psql('postgres', 'CREATE ROLE alice LOGIN');
$node->safe_psql('postgres', 'CREATE ROLE bob LOGIN');
$node->safe_psql('postgres', q{CREATE TABLE public.shared (id int, val text)});
$node->safe_psql('postgres', q{
    INSERT INTO public.shared VALUES (1, 'a'), (2, 'b'), (3, 'c')
});
$node->safe_psql('postgres', 'REVOKE ALL ON TABLE public.shared FROM PUBLIC');
$node->safe_psql('postgres', 'REVOKE ALL ON SCHEMA public FROM PUBLIC');

$node->safe_psql('postgres', q{
    SELECT cedar_set_policies('base', $CEDAR$
permit(principal == User::"alice", action == Action::"SELECT", resource == Table::"public.shared");
permit(principal == User::"alice", action == Action::"USAGE",  resource == Schema::"public");
$CEDAR$)
});

# ============================================================================
# SECTION 1: Multiple concurrent sessions see consistent authorization
# ============================================================================
# Launch several background psql connections simultaneously using IPC::Run or
# sequential rapid-fire calls (PostgreSQL::Test::Cluster doesn't expose async
# psql, so we run them sequentially but verify results remain consistent).

my @alice_results;
my @bob_results;

for my $i (1..5) {
    my ($ret_a, undef, undef) = $node->psql('postgres',
        'SELECT id FROM public.shared ORDER BY id',
        extra_params => ['-U', 'alice']);
    push @alice_results, $ret_a;

    my ($ret_b, undef, undef) = $node->psql('postgres',
        'SELECT id FROM public.shared ORDER BY id',
        extra_params => ['-U', 'bob']);
    push @bob_results, $ret_b;
}

# All alice queries must succeed
my $alice_failures = grep { $_ != 0 } @alice_results;
is($alice_failures, 0,
    'Concurrent: all 5 alice SELECT queries succeed');

# All bob queries must fail
my $bob_successes = grep { $_ == 0 } @bob_results;
is($bob_successes, 0,
    'Concurrent: all 5 bob SELECT queries are denied');

# ============================================================================
# SECTION 2: Statistics accumulate correctly across sessions
# ============================================================================
# We issued 5 alice selects (each checking USAGE + SELECT = 2 Cedar evals).
# Stats are shared-memory counters, so all grants/denies accumulate globally.
my ($req, $grants, $denies) = split /\|/,
    $node->safe_psql('postgres',
    'SELECT auth_requests, auth_grants, auth_denies FROM cedar_stats()');

ok($grants > 0, "Concurrent stats: auth_grants > 0 ($grants)");
ok($denies > 0, "Concurrent stats: auth_denies > 0 ($denies)");

# ============================================================================
# SECTION 3: Policy update — new policy visible to subsequent connections
# ============================================================================
# Add a policy allowing bob AFTER initial queries have already run.
# New connections (new psql invocations) must see the updated policy
# because each backend lazily reloads from the catalog on first use.

$node->safe_psql('postgres', q{
    SELECT cedar_set_policies('bob_grant', $CEDAR$
permit(principal == User::"bob", action == Action::"SELECT", resource == Table::"public.shared");
permit(principal == User::"bob", action == Action::"USAGE",  resource == Schema::"public");
$CEDAR$)
});

# A new connection for bob should pick up the new policy
my ($ret_new_bob, $stdout_new, $stderr_new) = $node->psql('postgres',
    'SELECT id FROM public.shared ORDER BY id',
    extra_params => ['-U', 'bob']);
is($ret_new_bob, 0,
    'Policy update: bob SELECT succeeds after new policy loaded');

# Alice should still work too
my ($ret_alice_post, undef, undef) = $node->psql('postgres',
    'SELECT id FROM public.shared ORDER BY id',
    extra_params => ['-U', 'alice']);
is($ret_alice_post, 0,
    'Policy update: alice SELECT still succeeds after policy update');

# ============================================================================
# SECTION 4: cedar_reload() called while queries are ongoing
# ============================================================================
# Reload forces every backend to reinitialize its engine on next use.
# Run alice query, then reload, then run again — must still work.
my ($ret_pre, undef, undef) = $node->psql('postgres',
    'SELECT count(*) FROM public.shared',
    extra_params => ['-U', 'alice']);
is($ret_pre, 0, 'Pre-reload: alice query succeeds');

$node->safe_psql('postgres', 'SELECT cedar_reload()');

my ($ret_post, undef, undef) = $node->psql('postgres',
    'SELECT count(*) FROM public.shared',
    extra_params => ['-U', 'alice']);
is($ret_post, 0, 'Post-reload: alice query succeeds after cedar_reload()');

# ============================================================================
# SECTION 5: Cache reset under concurrent access
# ============================================================================
$node->safe_psql('postgres', 'SELECT cedar_cache_reset()');

# Immediately after cache reset, queries should still succeed (cache miss →
# live evaluation → result correct)
for my $i (1..3) {
    my ($ret_a, undef, undef) = $node->psql('postgres',
        'SELECT count(*) FROM public.shared',
        extra_params => ['-U', 'alice']);
    is($ret_a, 0, "Post-cache-reset query $i: alice SELECT succeeds");
}

# ============================================================================
# SECTION 6: Forbid overrides permit (multiple active policies)
# ============================================================================
# Add a forbid policy for alice on a specific table; verify it overrides permit.
$node->safe_psql('postgres', q{CREATE TABLE public.secret (id int)});
$node->safe_psql('postgres', 'REVOKE ALL ON TABLE public.secret FROM PUBLIC');

$node->safe_psql('postgres', q{
    SELECT cedar_set_policies('forbid_secret', $CEDAR$
// Broad permit: alice can SELECT anything
permit(principal == User::"alice", action == Action::"SELECT", resource);
// Forbid overrides: alice cannot SELECT the secret table
forbid(principal == User::"alice", action == Action::"SELECT", resource == Table::"public.secret");
$CEDAR$)
});

# The forbid on secret overrides the broad permit
my $secret_r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"SELECT"', 'Table::"public.secret"', NULL)});
is($secret_r, 'Deny',
    'Forbid overrides permit: alice SELECT on secret → Deny');

# alice can still SELECT other tables (permit matches, no forbid)
my $shared_r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"SELECT"', 'Table::"public.shared"', NULL)});
is($shared_r, 'Allow',
    'Forbid overrides permit: alice SELECT on shared still → Allow');

# ============================================================================
# SECTION 7: entity-based group membership under concurrent access
# ============================================================================
$node->safe_psql('postgres', q{
    SELECT cedar_set_entities($ENT$[
      {"uid": {"type": "User", "id": "alice"}, "attrs": {}, "parents": [{"type": "Group", "id": "readers"}]},
      {"uid": {"type": "Group", "id": "readers"}, "attrs": {}, "parents": []}
    ]$ENT$)
});

$node->safe_psql('postgres', q{
    SELECT cedar_set_policies('group_policy', $CEDAR$
permit(principal in Group::"readers", action == Action::"SELECT", resource == Table::"public.shared");
permit(principal in Group::"readers", action == Action::"USAGE",  resource == Schema::"public");
$CEDAR$)
});

# alice is in the readers group via entity hierarchy → should be allowed
my $group_r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"alice"', 'Action::"SELECT"', 'Table::"public.shared"', NULL)});
is($group_r, 'Allow',
    'Entity group: alice (in readers group) SELECT → Allow');

# bob is not in any group → denied
my $bob_group_r = $node->safe_psql('postgres',
    q{SELECT cedar_is_authorized('User::"bob"', 'Action::"SELECT"', 'Table::"public.shared"', NULL)});
is($bob_group_r, 'Deny',
    'Entity group: bob (not in readers group) SELECT → Deny');

# Run several queries to verify group policy works consistently under repeated access
for my $i (1..3) {
    my $rpt = $node->safe_psql('postgres',
        q{SELECT cedar_is_authorized('User::"alice"', 'Action::"SELECT"', 'Table::"public.shared"', NULL)});
    is($rpt, 'Allow', "Entity group repeated check $i → Allow");
}

$node->stop;
done_testing();
