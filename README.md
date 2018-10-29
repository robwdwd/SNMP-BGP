# NAME

SNMP::BGP - Get BGP neighbour informaiton from network devices using SNMP.

# VERSION

Version 0.01

# SYNOPSIS

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

# SUBROUTINES/METHODS

## new

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

## close

Close the BGP::SNMP session. This closes down the Net::SNMP sessions and clears the neighbours.

## hasError

Returns 1 (true) if the object has an error. You can retrieve the error message with
the errorMsg() method.

## errorMsg

Returns the last error message. Use hasError() to check if a device
has an error, relying on this to return an empty string to check for
errors might produce unexpected results (sometimes non fatal error
messages can be stored here.)

## getNeighbours

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

## getIOSXRNei

Get BGP neighbours on a device running IOS-XR. You should call getNeighbours()
rather than this one directly.

## getJunOSNei

Get BGP neighbours on a device running JunOS. You should call getNeighbours()
rather than this one directly.

## getIOSNei

Get BGP neighbours on a device running IOS. You should call getNeighbours()
rather than this one directly.

## extractCiscoIP

Extracts the IP address from the OID using a regular expression. See getIOSXRNei() subroutine for example
regular expressions.

This method shouldn't usually called directly but used in the getIOSXRNei() and getIOSNei() methods internally.

    my $oid_re = '1\.3\.6\.1\.4\.1\.9\.9\.187\.1\.2\.5\.1\.\d+\.[12]\.\d{1,2}\.(.+)$';
    my $oid    = '1.3.6.1.4.1.9.9.187.1.2.5.1.29.1.4.192.168.1.1'

    my $ip = $bgp->extractCiscoIP($oid, $oid_re)

    print $ip; # 192.168.1.1

## getIPDetails

Get details on the IP address, such as version (v4 or v6). 
If its private addressing and so forth. Sets these to undef
if the IP is not valid IP version.

# INTERNAL METHODS

These methods should not be called directly but are used internally
by the module.

## \_init

init function to validate arguments, not called directly.

## \_startSession

Start the NET::SNMP session.

# AUTHOR

Rob Woodward, `<robwdwd at icloud.com>`

# BUGS

Please report bugs, issues, feature requests and improvements on gitHub. [https://github.com/robwwd/SNMP-BGP/](https://github.com/robwwd/SNMP-BGP/)

# SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc SNMP::BGP

You can also look for information at:

- GitHub issue tracker

    [https://github.com/robwwd/SNMP-BGP/issues](https://github.com/robwwd/SNMP-BGP/issues)

- Source Code

    [https://github.com/robwwd/SNMP-BGP/](https://github.com/robwwd/SNMP-BGP/)

# ACKNOWLEDGEMENTS

# LICENSE AND COPYRIGHT

Copyright 2018 Rob Woodward.

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at [http://mozilla.org/MPL/2.0/](http://mozilla.org/MPL/2.0/).
