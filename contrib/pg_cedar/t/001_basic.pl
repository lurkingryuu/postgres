
use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# Initialize and start a node with pg_cedar preloaded
my $node = PostgreSQL::Test::Cluster->new('main');
$node->init;
$node->append_conf('postgresql.conf',
	"shared_preload_libraries = 'pg_cedar'");
$node->start;

# Setup extension
$node->safe_psql('postgres', 'CREATE EXTENSION pg_cedar');

# --- Test 1: Extension is enabled ---
my $enabled = $node->safe_psql('postgres', 'SELECT cedar_is_enabled()');
is($enabled, 't', 'Extension is enabled by default');

# --- Test 2: Load policies and test manual authorization ---
$node->safe_psql('postgres',
	"SELECT cedar_set_policies('default', "
	. "'permit(principal == User::\"\"alice\"\", action == Action::\"\"SELECT\"\", resource);')");

my $allow = $node->safe_psql('postgres',
	"SELECT cedar_is_authorized("
	. "'User::\"\"alice\"\"', 'Action::\"\"SELECT\"\"', 'Table::\"\"public.t\"\"', NULL)");
is($allow, 'Allow', 'Alice is authorized by Cedar policy');

my $deny = $node->safe_psql('postgres',
	"SELECT cedar_is_authorized("
	. "'User::\"\"bob\"\"', 'Action::\"\"SELECT\"\"', 'Table::\"\"public.t\"\"', NULL)");
is($deny, 'Deny', 'Bob is denied by Cedar policy');

# --- Test 3: Authorization hook integration ---
# Create test role and table
$node->safe_psql('postgres', 'CREATE ROLE alice LOGIN');
$node->safe_psql('postgres', 'CREATE TABLE public.test_cedar (id int)');
$node->safe_psql('postgres',
	'REVOKE ALL ON TABLE public.test_cedar FROM PUBLIC');
$node->safe_psql('postgres',
	'REVOKE ALL ON SCHEMA public FROM PUBLIC');

# Update policy for hook-based authorization
$node->safe_psql('postgres',
	"SELECT cedar_set_policies('hook_policy', "
	. "'permit(principal == User::\"\"alice\"\", action == Action::\"\"SELECT\"\", resource == Table::\"\"public.test_cedar\"\");')");

# Alice should be able to SELECT (through the hook)
my ($ret, $stdout, $stderr) = $node->psql('postgres',
	'SELECT * FROM public.test_cedar',
	extra_params => ['-U', 'alice']);
is($ret, 0, 'Alice authorized to SELECT via Cedar hook');

# Bob should be denied
$node->safe_psql('postgres', 'CREATE ROLE bob LOGIN');
($ret, $stdout, $stderr) = $node->psql('postgres',
	'SELECT * FROM public.test_cedar',
	extra_params => ['-U', 'bob']);
isnt($ret, 0, 'Bob denied SELECT via Cedar hook');
like($stderr, qr/permission denied/, 'Error message indicates permission denied');

# --- Test 4: Validate and explain ---
my $valid = $node->safe_psql('postgres', 'SELECT cedar_validate()');
is($valid, 'OK', 'Policy validation passes');

my $diag = $node->safe_psql('postgres',
	"SELECT cedar_explain_decision("
	. "'User::\"\"alice\"\"', 'Action::\"\"SELECT\"\"', 'Table::\"\"public.test_cedar\"\"', NULL)");
like($diag, qr/reasons/, 'Diagnostics contains reasons');

# --- Test 5: Reload ---
my $reload = $node->safe_psql('postgres', 'SELECT cedar_reload()');
is($reload, 't', 'Reload succeeds');

# Cleanup
$node->stop;

done_testing();
