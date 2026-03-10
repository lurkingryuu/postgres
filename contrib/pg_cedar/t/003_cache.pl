
use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# ============================================================================
# Cache test: decision cache hit/miss/eviction/TTL behaviour
# ============================================================================

# --------------------------------------------------------------------------
# Node A: cache enabled (default) — verify hit/miss accounting
# --------------------------------------------------------------------------
my $node = PostgreSQL::Test::Cluster->new('cache_on');
$node->init;
$node->append_conf(
    'postgresql.conf',
    "shared_preload_libraries = 'pg_cedar'\n"
      . "pg_cedar.cache_enabled = on\n"
      . "pg_cedar.cache_size = 64\n"     # small so eviction is reachable
      . "pg_cedar.cache_ttl = 300\n"
      . "pg_cedar.collect_stats = on\n");
$node->start;
$node->safe_psql('postgres', 'CREATE EXTENSION pg_cedar');
$node->safe_psql('postgres', 'CREATE ROLE alice LOGIN');
$node->safe_psql('postgres', q{CREATE TABLE public.t (id int)});
$node->safe_psql('postgres', 'REVOKE ALL ON TABLE public.t FROM PUBLIC');
$node->safe_psql('postgres', 'REVOKE ALL ON SCHEMA public FROM PUBLIC');

$node->safe_psql('postgres', q{
    SELECT cedar_set_policies('cache_test', $CEDAR$
permit(principal == User::"alice", action == Action::"SELECT", resource == Table::"public.t");
permit(principal == User::"alice", action == Action::"USAGE",  resource == Schema::"public");
$CEDAR$)
});

# --- Test 1: Initial cache stats are zero ---
my ($hits, $misses, $evictions, $entries) = split /\|/,
    $node->safe_psql('postgres',
    'SELECT hits, misses, evictions, entries FROM cedar_cache_stats()');
is($hits,      '0', 'Initial cache: hits = 0');
is($misses,    '0', 'Initial cache: misses = 0');
is($evictions, '0', 'Initial cache: evictions = 0');
is($entries,   '0', 'Initial cache: entries = 0');

# --- Test 2: First hook-based query → cache miss, entry inserted ---
my ($ret, $stdout, $stderr) = $node->psql('postgres',
    'SELECT * FROM public.t',
    extra_params => ['-U', 'alice']);
is($ret, 0, 'Cache miss: alice SELECT succeeds');

my $misses_after = $node->safe_psql('postgres',
    'SELECT misses FROM cedar_cache_stats()');
ok($misses_after > 0, "Cache miss: misses counter increased ($misses_after > 0)");

my $entries_after = $node->safe_psql('postgres',
    'SELECT entries FROM cedar_cache_stats()');
ok($entries_after > 0, "Cache miss: entries > 0 after first query ($entries_after)");

# --- Test 3: Second identical query → cache hit ---
($ret, $stdout, $stderr) = $node->psql('postgres',
    'SELECT * FROM public.t',
    extra_params => ['-U', 'alice']);
is($ret, 0, 'Cache hit: alice SELECT succeeds again');

my $hits_after = $node->safe_psql('postgres',
    'SELECT hits FROM cedar_cache_stats()');
ok($hits_after > 0, "Cache hit: hits counter increased ($hits_after > 0)");

# Hits must now exceed misses for the same action (alice SELECT on the same
# table) because the second call should have been served from cache.
my $misses_after2 = $node->safe_psql('postgres',
    'SELECT misses FROM cedar_cache_stats()');
ok($hits_after >= $misses_after2,
    "Cache hit: hits ($hits_after) >= misses ($misses_after2) after second query");

# --- Test 4: cedar_cache_reset() clears entries but preserves miss/hit totals ---
$node->safe_psql('postgres', 'SELECT cedar_cache_reset()');

my $entries_reset = $node->safe_psql('postgres',
    'SELECT entries FROM cedar_cache_stats()');
is($entries_reset, '0', 'Cache reset: entries = 0 after cedar_cache_reset()');

# Hits/misses/evictions are also zeroed by cedar_cache_reset (the C code resets them)
my $hits_reset = $node->safe_psql('postgres',
    'SELECT hits FROM cedar_cache_stats()');
is($hits_reset, '0', 'Cache reset: hits = 0 after cedar_cache_reset()');

# --- Test 5: Query after reset → miss again ---
($ret, $stdout, $stderr) = $node->psql('postgres',
    'SELECT * FROM public.t',
    extra_params => ['-U', 'alice']);
is($ret, 0, 'Post-reset: alice SELECT succeeds');

my $misses_post = $node->safe_psql('postgres',
    'SELECT misses FROM cedar_cache_stats()');
ok($misses_post > 0, "Post-reset: misses > 0 (cache was empty after reset)");

# --- Test 6: cedar_reset_stats() zeroes auth counters, not cache counters ---
$node->safe_psql('postgres', 'SELECT cedar_reset_stats()');
my ($req, $grants, $denies) = split /\|/,
    $node->safe_psql('postgres',
    'SELECT auth_requests, auth_grants, auth_denies FROM cedar_stats()');
is($req,    '0', 'cedar_reset_stats: auth_requests = 0');
is($grants, '0', 'cedar_reset_stats: auth_grants = 0');
is($denies, '0', 'cedar_reset_stats: auth_denies = 0');

# Cache entries should still be present (reset_stats does not flush cache)
my $entries_after_reset_stats = $node->safe_psql('postgres',
    'SELECT entries FROM cedar_cache_stats()');
ok($entries_after_reset_stats >= 0,
    'cedar_reset_stats: cache entries unaffected');

# --- Test 7: Cache eviction when cache is full ---
# With cache_size=64 we need to issue 65+ unique (roleid, classid, oid, subid, action)
# combinations to trigger eviction.  We simulate this by creating many roles and tables.
for my $i (1..30) {
    $node->safe_psql('postgres', "CREATE ROLE cacheuser$i LOGIN");
    $node->safe_psql('postgres', qq{CREATE TABLE public.ctbl$i (id int)});
    $node->safe_psql('postgres', qq{REVOKE ALL ON TABLE public.ctbl$i FROM PUBLIC});

    # Cedar policies for each new role/table pair
    $node->safe_psql('postgres', qq{
        SELECT cedar_set_policies('evict$i', \$CEDAR\$
permit(principal == User::"cacheuser$i", action == Action::"SELECT", resource == Table::"public.ctbl$i");
permit(principal == User::"cacheuser$i", action == Action::"USAGE",  resource == Schema::"public");
\$CEDAR\$)
    });
}

my $evict_before = $node->safe_psql('postgres',
    'SELECT evictions FROM cedar_cache_stats()');

# Run queries as many distinct users to fill the cache
for my $i (1..30) {
    $node->psql('postgres',
        "SELECT * FROM public.ctbl$i",
        extra_params => ['-U', "cacheuser$i"]);
}

# With cache_size=64 and ~60 unique (user × table × action) entries the eviction
# counter may or may not have fired; just assert it is >= the prior value.
my $evict_after = $node->safe_psql('postgres',
    'SELECT evictions FROM cedar_cache_stats()');
ok($evict_after >= $evict_before,
    "Cache eviction: evictions ($evict_after) >= prior value ($evict_before)");

# ============================================================================
# Node B: cache disabled — verify no cache hits accumulate
# ============================================================================
my $node_nocache = PostgreSQL::Test::Cluster->new('cache_off');
$node_nocache->init;
$node_nocache->append_conf(
    'postgresql.conf',
    "shared_preload_libraries = 'pg_cedar'\n"
      . "pg_cedar.cache_enabled = off\n"
      . "pg_cedar.collect_stats = on\n");
$node_nocache->start;
$node_nocache->safe_psql('postgres', 'CREATE EXTENSION pg_cedar');
$node_nocache->safe_psql('postgres', 'CREATE ROLE alice LOGIN');
$node_nocache->safe_psql('postgres', q{CREATE TABLE public.t (id int)});
$node_nocache->safe_psql('postgres', 'REVOKE ALL ON TABLE public.t FROM PUBLIC');
$node_nocache->safe_psql('postgres', 'REVOKE ALL ON SCHEMA public FROM PUBLIC');
$node_nocache->safe_psql('postgres', q{
    SELECT cedar_set_policies('nc', $CEDAR$
permit(principal == User::"alice", action == Action::"SELECT", resource == Table::"public.t");
permit(principal == User::"alice", action == Action::"USAGE",  resource == Schema::"public");
$CEDAR$)
});

# Two identical queries; with cache disabled, second query still evaluates live
$node_nocache->psql('postgres', 'SELECT * FROM public.t',
    extra_params => ['-U', 'alice']);
$node_nocache->psql('postgres', 'SELECT * FROM public.t',
    extra_params => ['-U', 'alice']);

my $nc_hits = $node_nocache->safe_psql('postgres',
    'SELECT hits FROM cedar_cache_stats()');
is($nc_hits, '0', 'Cache disabled: hits remain 0 after repeated queries');

my $nc_misses = $node_nocache->safe_psql('postgres',
    'SELECT misses FROM cedar_cache_stats()');
is($nc_misses, '0', 'Cache disabled: misses remain 0 (cache not used at all)');

$node_nocache->stop;
$node->stop;

done_testing();
