#!perl -T
use 5.006;
use strict;
use warnings;
use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'SNMP::BGP' ) || print "Bail out!\n";
}

diag( "Testing SNMP::BGP $SNMP::BGP::VERSION, Perl $], $^X" );
