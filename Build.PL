use 5.006;
use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name        => 'SNMP::BGP',
    license            => 'open_source',
    dist_author        => q{Rob Woodward <robwdwd@icloud.com>},
    dist_version_from  => 'lib/SNMP/BGP.pm',
    release_status     => 'stable',
    configure_requires => {
        'Module::Build' => '0',
    },
    build_requires => {
        'Test::More' => '0',
    },
    requires => {
        'Net::SNMP'        => '0',
        'Params::Validate' => '0',
        'Net::IPv6Addr' => '0',
        'List::MoreUtils' => '0',
    },
    add_to_cleanup => ['SNMP-BGP-*'],
);

$builder->create_build_script();
