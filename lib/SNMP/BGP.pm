package SNMP::BGP;

use 5.006;
use strict;
use warnings;

use Carp;

use Params::Validate qw( validate SCALAR UNDEF );
use Data::Validate::IP qw(is_ip is_ipv4 is_ipv6 is_private_ipv4 is_private_ipv6);
use Net::IPv6Addr;
use Net::SNMP;
use List::MoreUtils qw (firstval natatime);

use Data::Dump qw(dump);

=head1 NAME

SNMP::BGP - Get BGP neighbour informaiton from network devices using SNMP.

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Get BGP neighbour details from a network devices running BGP routing protocol.

Supported operating systesm are JunOS, IOS, IOS-XE, IOS-XR.

    use warnings;
    use strict;
    use Data::Dump qw(dump);

    use SNMP::BGP;

    my $bgp = SNMP::BGP->new(
        hostname     => 'router.example.net',
        os           => 'IOS-XR',
        username     => 'SNMPUser',
        authpassword => 'SNMPPassword',
        privpassword => 'PrivacyPass',
        version      => 3,
    );

    unless (defined($bgp)) {
        print "Error creating new SNMP::BGP session\n";
    }

    if ($bgp->hasError()) {
        print $bgp->errorMsg() . "\n";
    } else {
        my $neighbours = $bgp->getNeighbours();

        if ($bgp->hasError()) {
            print $bgp->errorMsg() . "\n";
        } else {
            dump ($neighbours);
        }
    }


=head1 SUBROUTINES/METHODS

=head2 new

    $bgpDevice = SNMP::BGP->new(
        Hostname        => $hostname,
        Os              => $os
        [Version        => $version,]       # 2 or 3, default 2
        [Community      => $community,]     # Default 'public'
        [Username       => $snmpusername,]  # Default 'username', sets noAuthNoPriv when used alone.
        [Authpassword   => $authpassword,]  # sets authNoPriv
        [Authprotocol   => $authprotocol,]  # md5|sha, default 'sha'
        [Privpassword   => $privpassword,]  # authpassword must be used, sets 'authPriv'
        [Privprotocol   => $privprotocol,]  # des|aes, default 'aes'
        [Timeout        => $snmptimeout,]   # default 5
        [Debug          => $debug]          # default 0
        );


Creates a new SNMP::BGP object. SNMP Authentication either with communities or user based follow
the same rules as NET::SNMP.

=cut

sub new {
    my $class   = shift;
    my %options = @_;

    my $self = {
        has_err     => 0,
        errormsg    => undef,
        snmpSession => undef,
        result      => {},
        options     => {},
        state_table => {
            1 => 'idle',
            2 => 'connect',
            3 => 'active',
            4 => 'opensent',
            5 => 'openconfirm',
            6 => 'established'
        }
    };

    bless($self, $class);

    $self->{'options'} = $self->_init(%options);

    unless (defined $self->{'options'}) {
        return undef;
    }

    $self->_startSession;

    return ($self);
}

=head2 close

Close the BGP::SNMP session. This closes down the Net::SNMP sessions and clears the neighbours.

=cut

sub close {
    my $self = shift;

    $self->{'snmpSession'}->close() if ($self->{'snmpSession'});
    $self->{'results'} = undef;

    return 1;
}

=head2 hasError

Returns 1 (true) if the object has an error. You can retrieve the error message with
the errorMsg() method.

=cut

sub hasError {
    my $self = shift;

    return $self->{'has_err'};
}

=head2 errorMsg

Returns the last error message. Use hasError() to check if a device
has an error, relying on this to return an empty string to check for
errors might produce unexpected results (sometimes non fatal error
messages can be stored here.)

=cut

sub errorMsg {
    my $self = shift;

    return $self->{'errormsg'};
}

=head2 getNeighbours

Get BGP neighbours on the device depending on the software, JunOS, IOS-XR etc.

Returns a hashref indexed on IP address of the BGP neighbours found on the device.

 "172.20.60.220"  => {
                        as => 1234,
                        ip_details => { private => 1, version => 4 },
                        pfx_accepted => 0,
                        state => 1,
                        status => "idle",

                },
  "4.4.4.1" => {
                    as => 1234,
                    ip_details => { private => 0, version => 4 },
                    pfx_accepted => 1000,
                    state => 6,
                    status => "established",
               },
  ...

=cut

sub getNeighbours {

    my $self = shift;

    if ($self->{'options'}->{'os'} eq 'IOS-XR' || $self->{'options'}->{'os'} eq 'IOS-XE') {
        $self->getIOSXRNei();
    } elsif ($self->{'options'}->{'os'} eq 'JunOS') {
        $self->getJunOSNei();
    } elsif ($self->{'options'}->{'os'} eq 'IOS') {
        $self->getIOSNei();
    }

    return $self->{'results'};
}

=head2 getIOSXRNei

Get BGP neighbours on a device running IOS-XR. You should call getNeighbours()
rather than this one directly.

=cut

sub getIOSXRNei {

    my $self = shift;

    my $cbgpPeer2RemoteAs         = '1.3.6.1.4.1.9.9.187.1.2.5.1.11';
    my $cbgpPeer2State            = '1.3.6.1.4.1.9.9.187.1.2.5.1.3';
    my $cbgpPeer2AcceptedPrefixes = '1.3.6.1.4.1.9.9.187.1.2.8.1.1';

    my $cbgpPeer2Entry_re                 = '1\.3\.6\.1\.4\.1\.9\.9\.187\.1\.2\.5\.1\.\d+\.[12]\.\d{1,2}\.(.+)$';
    my $cbgpPeer2AddrFamilyPrefixEntry_re = '1\.3\.6\.1\.4\.1\.9\.9\.187\.1\.2\.8\.1\.\d+\.[12]\.\d{1,2}\.(.+)\.\d\.\d$';

    # Get peer state
    #
    my $cbgpPeer2Table = $self->{'snmpSession'}->get_entries(columns => [ $cbgpPeer2State, $cbgpPeer2RemoteAs ]);

    if (!defined($cbgpPeer2Table)) {
        $self->{'has_err'}  = 1;
        $self->{'errormsg'} = 'Error getting neighbours: ' . $self->{'snmpSession'}->error;
        return 0;
    }

    foreach (keys %$cbgpPeer2Table) {
        if (my ($base, $index) = $_ =~ /($cbgpPeer2RemoteAs)(.+)$/) {
            if (my $ip = $self->extractCiscoIP($_, $cbgpPeer2Entry_re)) {
                $self->{'results'}->{$ip} = {} unless exists $self->{'results'}->{$ip};
                $self->{'results'}->{$ip}->{'ip_details'} = $self->getIPDetails($ip);
                $self->{'results'}->{$ip}->{'as'}         = $cbgpPeer2Table->{$_};
                $self->{'results'}->{$ip}->{'state'}      = $cbgpPeer2Table->{ $cbgpPeer2State . $index };
                $self->{'results'}->{$ip}->{'status'}     = $self->{'state_table'}->{ $cbgpPeer2Table->{ $cbgpPeer2State . $index } };
            }
        }
    }

    my $cbgpPeer2AddrFamilyPrefixTable = $self->{'snmpSession'}->get_entries(columns => [$cbgpPeer2AcceptedPrefixes]);

    if (!defined($cbgpPeer2AddrFamilyPrefixTable)) {
        $self->{'has_err'}  = 1;
        $self->{'errormsg'} = 'Error getting BGP neighbours prefix count: ' . $self->{'snmpSession'}->error;
        return 0;
    }

    foreach (keys %$cbgpPeer2AddrFamilyPrefixTable) {
        if (my $ip = $self->extractCiscoIP($_, $cbgpPeer2AddrFamilyPrefixEntry_re)) {
            $self->{'results'}->{$ip} = {} unless exists $self->{'results'}->{$ip};
            $self->{'results'}->{$ip}->{'pfx_accepted'} = $cbgpPeer2AddrFamilyPrefixTable->{$_} || 0;
        }
    }

    return 1;
}

=head2 getJunOSNei

Get BGP neighbours on a device running JunOS. You should call getNeighbours()
rather than this one directly.

=cut

sub getJunOSNei {

    my $self = shift;

    my $jnxBgpM2PeerState          = '1.3.6.1.4.1.2636.5.1.1.2.1.1.1.2';
    my $jnxBgpM2PeerRemoteAddrType = '1.3.6.1.4.1.2636.5.1.1.2.1.1.1.10';
    my $jnxBgpM2PeerRemoteAddr     = '1.3.6.1.4.1.2636.5.1.1.2.1.1.1.11';
    my $jnxBgpM2PeerRemoteAs       = '1.3.6.1.4.1.2636.5.1.1.2.1.1.1.13';
    my $jnxBgpM2PeerIndex          = '1.3.6.1.4.1.2636.5.1.1.2.1.1.1.14';

    my $jnxBgpM2PrefixInPrefixesAccepted = '1.3.6.1.4.1.2636.5.1.1.2.6.2.1.8';

    # Get the prefix table.
    #
    my $jnxBgpM2PrefixCountersEntry_tbl =
      $self->{'snmpSession'}->get_entries(maxrepetitions => 3, columns => [$jnxBgpM2PrefixInPrefixesAccepted]);

    if (!defined($jnxBgpM2PrefixCountersEntry_tbl)) {
        $self->{'has_err'}  = 1;
        $self->{'errormsg'} = 'Error getting BGP neighbours prefix count: ' . $self->{'snmpSession'}->error;
        return 0;
    }

    my $jnxBgpM2PrefixCountersTable = {};

    foreach (keys %$jnxBgpM2PrefixCountersEntry_tbl) {
        if (my ($iid) = $_ =~ /$jnxBgpM2PrefixInPrefixesAccepted\.(\d+)\.\d+\.\d+$/) {
            $jnxBgpM2PrefixCountersTable->{$iid} = $jnxBgpM2PrefixCountersEntry_tbl->{$_};
        }
    }

    # Get Peer table.
    #
    my $jnxBgpM2PeerTable = $self->{'snmpSession'}->get_entries(
        maxrepetitions => 3,
        columns        => [ $jnxBgpM2PeerIndex, $jnxBgpM2PeerRemoteAddr, $jnxBgpM2PeerRemoteAs, $jnxBgpM2PeerRemoteAddrType, $jnxBgpM2PeerState ]
    );

    if (!defined($jnxBgpM2PeerTable)) {
        $self->{'has_err'}  = 1;
        $self->{'errormsg'} = 'Error getting neighbours: ' . $self->{'snmpSession'}->error;
        return 0;
    }

    foreach (keys %$jnxBgpM2PeerTable) {

        if (my ($base, $index) = $_ =~ /($jnxBgpM2PeerRemoteAddrType)(.+)$/) {

            my $iid = $jnxBgpM2PeerTable->{ $jnxBgpM2PeerIndex . $index };
            my $ip;

            if ($jnxBgpM2PeerTable->{$_} == 1) {
                $ip = join('.', unpack("C*", pack("H*", substr($jnxBgpM2PeerTable->{ $jnxBgpM2PeerRemoteAddr . $index }, 2))));
            } elsif ($jnxBgpM2PeerTable->{$_} == 2) {
                $ip = Net::IPv6Addr::to_string_compressed(join(':', unpack("(A4)*", substr($jnxBgpM2PeerTable->{ $jnxBgpM2PeerRemoteAddr . $index }, 2))));
            } else {
                printf(STDERR "WARNING: Unknown IP address type found: %s on %s.\n", $jnxBgpM2PeerTable->{$_}, $self->{'options'}->{'Hostname'})
                  if $self->{'options'}->{'debug'};
                next;
            }

            next unless $ip;
            next unless (is_ip($ip));

            $self->{'results'}->{$ip}->{'state'}        = $jnxBgpM2PeerTable->{ $jnxBgpM2PeerState . $index };
            $self->{'results'}->{$ip}->{'ip_details'}   = $self->getIPDetails($ip);
            $self->{'results'}->{$ip}->{'status'}       = $self->{'state_table'}->{ $jnxBgpM2PeerTable->{ $jnxBgpM2PeerState . $index } };
            $self->{'results'}->{$ip}->{'as'}           = $jnxBgpM2PeerTable->{ $jnxBgpM2PeerRemoteAs . $index };
            $self->{'results'}->{$ip}->{'pfx_accepted'} = $jnxBgpM2PrefixCountersTable->{$iid} || 0;
        }
    }

    return 1;
}

=head2 getIOSNei

Get BGP neighbours on a device running IOS. You should call getNeighbours()
rather than this one directly.

=cut

sub getIOSNei {

    my $self = shift;

    my ($session, $hostname, $neighbours) = @_;

    my $cbgpPeer2RemoteAs         = '1.3.6.1.2.1.15.3.1.9';
    my $cbgpPeer2State            = '1.3.6.1.2.1.15.3.1.2';
    my $cbgpPeer2AcceptedPrefixes = '1.3.6.1.4.1.9.9.187.1.2.4.1.1';

    my $cbgpPeer2Entry_re                 = '1\.3\.6\.1\.2\.1\.15\.3\.1\.\d+\.(.+)$';
    my $cbgpPeer2AddrFamilyPrefixEntry_re = '1\.3\.6\.1\.4\.1\.9\.9\.187\.1\.2\.4\.1\.\d+\.(.+)\.\d+\.\d+$';

    # Get peer state
    #
    my $cbgpPeer2Table = $self->{'snmpSession'}->get_entries(columns => [ $cbgpPeer2State, $cbgpPeer2RemoteAs ]);

    if (!defined($cbgpPeer2Table)) {
        $self->{'has_err'}  = 1;
        $self->{'errormsg'} = 'Error getting neighbours: ' . $self->{'snmpSession'}->error;
        return 0;
    }

    foreach (keys %$cbgpPeer2Table) {
        if (my ($base, $index) = $_ =~ /($cbgpPeer2RemoteAs)(.+)$/) {
            if (my $ip = $self->extractCiscoIP($_, $cbgpPeer2Entry_re)) {
                $self->{'results'}->{$ip} = {} unless exists $self->{'results'}->{$ip};
                $self->{'results'}->{$ip}->{'ip_details'} = $self->getIPDetails($ip);
                $self->{'results'}->{$ip}->{'as'}         = $cbgpPeer2Table->{$_};
                $self->{'results'}->{$ip}->{'state'}      = $cbgpPeer2Table->{ $cbgpPeer2State . $index };
                $self->{'results'}->{$ip}->{'status'}     = $self->{'state_table'}->{ $cbgpPeer2Table->{ $cbgpPeer2State . $index } };
                $self->{'results'}->{$ip}->{'pfx_accepted'} = 0;
            }
        }
    }

    my $cbgpPeer2AddrFamilyPrefixTable = $self->{'snmpSession'}->get_entries(columns => [$cbgpPeer2AcceptedPrefixes]);

    # Some older IOS does not support this OID.
    #
    if (!defined($cbgpPeer2AddrFamilyPrefixTable)) {
        $self->{'has_err'}  = 0;
        $self->{'errormsg'} = 'Error getting BGP neighbours prefix count: ' . $self->{'snmpSession'}->error;
        return 1;
    } else {

      foreach (keys %$cbgpPeer2AddrFamilyPrefixTable) {
          if (my $ip = $self->extractCiscoIP($_, $cbgpPeer2AddrFamilyPrefixEntry_re)) {
              $self->{'results'}->{$ip} = {} unless exists $self->{'results'}->{$ip};
              $self->{'results'}->{$ip}->{'pfx_accepted'} = $cbgpPeer2AddrFamilyPrefixTable->{$_} || 0;
          }
      }
    }

    return 1;
}

=head2 extractCiscoIP

Extracts the IP address from the OID using a regular expression. See getIOSXRNei() subroutine for example
regular expressions.

This method shouldn't usually called directly but used in the getIOSXRNei() and getIOSNei() methods internally.

    my $oid_re = '1\.3\.6\.1\.4\.1\.9\.9\.187\.1\.2\.5\.1\.\d+\.[12]\.\d{1,2}\.(.+)$';
    my $oid    = '1.3.6.1.4.1.9.9.187.1.2.5.1.29.1.4.192.168.1.1'

    my $ip = $bgp->extractCiscoIP($oid, $oid_re)

    print $ip; # 192.168.1.1

=cut

sub extractCiscoIP {

    my $self = shift;

    my ($oid, $re) = @_;

    if ($oid =~ /$re/) {

        my $ip = $1;

        # Check if IPv4 or IPv6.

        my $count = $ip =~ tr/././;

        if ($count > 3) {

            # Convert IPv6 address to Hex
            my @ipv6;
            my $it = natatime(2, map ({ sprintf("%02x", $_) } split('\.', $ip)));

            while (my @v = $it->()) {
                push(@ipv6, join('', @v));
            }

            return Net::IPv6Addr::to_string_compressed(join ':', @ipv6);
        }
        return $ip;
    }
    return 0;
}

=head2 getIPDetails

Get details on the IP address, such as version (v4 or v6). 
If its private addressing and so forth. Sets these to undef
if the IP is not valid IP version.

=cut

sub getIPDetails {
    my $self = shift;
    my $ip   = shift;

    my $ipDetails = {};

    if (is_ipv4($ip)) {
        $ipDetails->{'version'} = 4;

        if (is_private_ipv4($ip)) {
            $ipDetails->{'private'} = 1;
        } else {
            $ipDetails->{'private'} = 0;
        }

    } elsif (is_ipv6($ip)) {
        $ipDetails->{'version'} = 6;

        if (is_private_ipv6($ip)) {
            $ipDetails->{'private'} = 1;
        } else {
            $ipDetails->{'private'} = 0;
        }

    } else {
        $ipDetails->{'version'} = undef;
        $ipDetails->{'private'} = undef;
    }

    return $ipDetails;
}

=head1 INTERNAL METHODS

These methods should not be called directly but are used internally
by the module.

=head2 _init

init function to validate arguments, not called directly.

=cut

sub _init {
    my $self = shift;

    my %p = validate(
        @_,
        {
            Hostname => {
                type => SCALAR
            },
            Os => {
                type => SCALAR
            },
            Version => {
                type     => SCALAR,
                default  => 2,
                optional => 1,
            },
            Community => {
                type     => SCALAR,
                default  => 'public',
                optional => 1,
            },
            Username => {
                type     => SCALAR | UNDEF,
                default  => 'username',
                optional => 1,
            },
            Authpassword => {
                type     => SCALAR | UNDEF,
                optional => 1,
            },
            Authprotocol => {
                type     => SCALAR,
                optional => 1,
                default  => 'sha',
            },
            Privpassword => {
                type     => SCALAR | UNDEF,
                optional => 1,
                depends  => ['Authpassword'],
            },
            Privprotocol => {
                type     => SCALAR | UNDEF,
                optional => 1,
                default  => 'aes',
            },
            Timeout => {
                type    => SCALAR,
                default => 5
            },
            Debug => {
                type    => SCALAR | UNDEF,
                default => 0
            },
        }
    );

    my $options = {
        'os'    => $p{'Os'},
        'debug' => $p{'Debug'},
        'snmp'  => {}
    };

    if ($p{'Version'} == 3) {
        unless (defined $p{'Username'}) {
            croak "ERROR: SNMP v3 session needed but missing SNMPv3 credentials.";
            return undef;
        }

        $options->{'snmp'}->{'Hostname'}     = $p{'Hostname'};
        $options->{'snmp'}->{'Version'}      = $p{'Version'};
        $options->{'snmp'}->{'Username'}     = $p{'Username'};
        $options->{'snmp'}->{'Authpassword'} = $p{'Authpassword'} if (defined $p{'Authpassword'});
        $options->{'snmp'}->{'Authprotocol'} = $p{'Authprotocol'} if (defined $p{'Authpassword'});
        $options->{'snmp'}->{'Privpassword'} = $p{'Privpassword'} if (defined $p{'Privpassword'});
        $options->{'snmp'}->{'Privprotocol'} = $p{'Privprotocol'} if (defined $p{'Privpassword'});
        $options->{'snmp'}->{'Timeout'}      = $p{'Timeout'};
        $options->{'snmp'}->{'Debug'}        = $p{'Debug'} if ($p{'Debug'});

    } elsif ($p{'Version'} == 2) {
        unless (defined $p{'Community'}) {
            croak "ERROR: SNMP v2c session needed but missing community string.";
            return undef;
        }

        $options->{'snmp'}->{'Hostname'}  = $p{'Hostname'};
        $options->{'snmp'}->{'Version'}   = $p{'Version'};
        $options->{'snmp'}->{'Community'} = $p{'Community'};
        $options->{'snmp'}->{'Timeout'}   = $p{'Timeout'};
        $options->{'snmp'}->{'Debug'}     = $p{'Debug'} if ($p{'Debug'});

    } else {
        croak "ERROR: SNMP version not supported.";
        return undef;
    }
    return $options;
}

=head2 _startSession

Start the NET::SNMP session.

=cut

sub _startSession {
    my $self = shift;

    my ($session, $error) = Net::SNMP->session(%{ $self->{'options'}->{'snmp'} });

    if (!defined($session)) {
        $self->{'errormsg'} = $error;
        $self->{'has_err'}  = 1;
        printf(STDERR "ERROR: Unable create SNMP session: %s.\n", $error) if $self->{'options'}->{'debug'};
        return 0;
    }

    if ($session->error()) {
        $self->{'errormsg'} = $session->error;
        $self->{'has_err'}  = 1;
        printf(STDERR "ERROR: Unable create SNMP session: %s.\n", $session->error) if $self->{'options'}->{'debug'};
    }

    print(STDERR "DEBUG: SNMP session creation sucessfull.\n") if $self->{'options'}->{'debug'};
    $self->{'snmpSession'} = $session;

    return 1;
}

=head1 AUTHOR

Rob Woodward, C<< <robwdwd at icloud.com> >>

=head1 BUGS

Please report bugs, issues, feature requests and improvements on gitHub. L<https://github.com/robwwd/SNMP-BGP/>

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc SNMP::BGP


You can also look for information at:

=over 4

=item * GitHub issue tracker

L<https://github.com/robwwd/SNMP-BGP/issues>

=item * Source Code

L<https://github.com/robwwd/SNMP-BGP/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2018 Rob Woodward.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at L<http://mozilla.org/MPL/2.0/>.


=cut

1;    # End of SNMP::BGP
