#!/usr/bin/perl
use strict;
use warnings;

# RPC program numbers
my %programs = (
    100000 => 'PORTMAPPER',
    100003 => 'NFS',
    100005 => 'MOUNTD',
    100021 => 'NLM',
);

# Auth flavors
my %auth_flavors = (
    0 => 'AUTH_NULL',
    1 => 'AUTH_UNIX',
    2 => 'AUTH_SHORT',
    3 => 'AUTH_DH',
    6 => 'RPCSEC_GSS',
);

# Accept states
my %accept_states = (
    0 => 'SUCCESS',
    1 => 'PROG_UNAVAIL',
    2 => 'PROG_MISMATCH',
    3 => 'PROC_UNAVAIL',
    4 => 'GARBAGE_ARGS',
    5 => 'SYSTEM_ERR',
);

# Get input filename from command line
my $input_file = $ARGV[0];

if (!defined $input_file) {
    print STDERR "Usage: $0 <strace-file>\n";
    print STDERR "  Decodes RPC communication from strace output\n";
    exit 1;
}

# Open input file
open(my $in, '<', $input_file) or die "Cannot open $input_file: $!";

my $packet_num = 0;

while (my $line = <$in>) {
    # Parse write() - outgoing packet
    if ($line =~ /(\d+):(\d+):(\d+)\.(\d+).*write\(\d+<socket:\[\d+\]>, "((?:\\x[0-9a-fA-F]{2})+)"/) {
        my ($h, $m, $s, $us, $hex_data) = ($1, $2, $3, $4, $5);
        my $timestamp = sprintf("%02d:%02d:%02d.%06d", $h, $m, $s, $us);
        my $data = parse_hex($hex_data);

        print "=" x 70 . "\n";
        print "Packet #" . ++$packet_num . " [$timestamp] CALL\n";
        print "=" x 70 . "\n";

        decode_rpc($data, 'CALL');
        print "\n";
    }
    # Parse read() - incoming packet
    elsif ($line =~ /(\d+):(\d+):(\d+)\.(\d+).*read\(\d+<socket:\[\d+\]>, "((?:\\x[0-9a-fA-F]{2})+)"/) {
        my ($h, $m, $s, $us, $hex_data) = ($1, $2, $3, $4, $5);
        my $timestamp = sprintf("%02d:%02d:%02d.%06d", $h, $m, $s, $us);
        my $data = parse_hex($hex_data);

        print "=" x 70 . "\n";
        print "Packet #" . ++$packet_num . " [$timestamp] REPLY\n";
        print "=" x 70 . "\n";

        decode_rpc($data, 'REPLY');
        print "\n";
    }
}

close($in);

# Parse hex string
sub parse_hex {
    my ($hex_str) = @_;
    my $binary = '';
    while ($hex_str =~ /\\x([0-9a-fA-F]{2})/g) {
        $binary .= chr(hex($1));
    }
    return $binary;
}

# Decode RPC message
sub decode_rpc {
    my ($data, $direction) = @_;
    my $offset = 0;

    # Record marker
    if (length($data) >= 4) {
        my $marker = get_u32(\$data, \$offset);
        my $last_frag = ($marker & 0x80000000) ? 1 : 0;
        my $frag_len = $marker & 0x7fffffff;

        print "RPC Record Marker:\n";
        print "  Last Fragment: " . ($last_frag ? "YES" : "NO") . "\n";
        print "  Fragment Length: $frag_len bytes\n\n";
    }

    # RPC header
    my $xid = get_u32(\$data, \$offset);
    my $msg_type = get_u32(\$data, \$offset);

    print "RPC Header:\n";
    print "  XID: 0x" . sprintf("%08x", $xid) . " ($xid)\n";
    print "  Message Type: " . ($msg_type == 0 ? "CALL" : "REPLY") . " ($msg_type)\n";

    if ($msg_type == 0) {
        decode_call(\$data, \$offset);
    } else {
        decode_reply(\$data, \$offset);
    }
}

# Decode RPC CALL
sub decode_call {
    my ($data_ref, $offset_ref) = @_;

    my $rpc_vers = get_u32($data_ref, $offset_ref);
    my $prog = get_u32($data_ref, $offset_ref);
    my $vers = get_u32($data_ref, $offset_ref);
    my $proc = get_u32($data_ref, $offset_ref);

    my $prog_name = $programs{$prog} || "UNKNOWN";

    print "  RPC Version: $rpc_vers\n";
    print "  Program: $prog ($prog_name)\n";
    print "  Program Version: $vers\n";
    print "  Procedure: $proc\n\n";

    # Decode credentials
    print "Credentials:\n";
    decode_auth($data_ref, $offset_ref);
    print "\n";

    # Decode verifier
    print "Verifier:\n";
    decode_auth($data_ref, $offset_ref);
    print "\n";
}

# Decode RPC REPLY
sub decode_reply {
    my ($data_ref, $offset_ref) = @_;

    my $reply_state = get_u32($data_ref, $offset_ref);
    print "  Reply State: " . ($reply_state == 0 ? "MSG_ACCEPTED" : "MSG_DENIED") . " ($reply_state)\n";

    if ($reply_state == 0) {
        print "\nVerifier:\n";
        decode_auth($data_ref, $offset_ref);
        print "\n";

        my $accept_state = get_u32($data_ref, $offset_ref);
        my $accept_name = $accept_states{$accept_state} || "UNKNOWN";
        print "Accept State: $accept_state ($accept_name)\n";
    }
}

# Decode authentication
sub decode_auth {
    my ($data_ref, $offset_ref) = @_;

    my $flavor = get_u32($data_ref, $offset_ref);
    my $length = get_u32($data_ref, $offset_ref);

    my $flavor_name = $auth_flavors{$flavor} || sprintf("UNKNOWN(0x%08x)", $flavor);
    print "  Flavor: $flavor_name ($flavor)\n";
    print "  Length: $length bytes\n";

    if ($length > 0) {
        my $auth_data = get_bytes($data_ref, $offset_ref, $length);
        if ($flavor == 1) {
            decode_auth_unix(\$auth_data);
        } else {
            print "  Data (hex): " . hex_dump($auth_data) . "\n";
        }
    }
}

# Decode AUTH_UNIX
sub decode_auth_unix {
    my ($data_ref) = @_;
    my $off = 0;

    my $stamp = get_u32($data_ref, \$off);
    my $machinename = get_string($data_ref, \$off);
    my $uid = get_u32($data_ref, \$off);
    my $gid = get_u32($data_ref, \$off);
    my $gids_len = get_u32($data_ref, \$off);

    print "  Timestamp: $stamp\n";
    print "  Machine: $machinename\n";
    print "  UID: $uid\n";
    print "  GID: $gid\n";
    print "  Additional GIDs: $gids_len\n";
}

# Helper functions
sub get_u32 {
    my ($data_ref, $offset_ref) = @_;
    my $val = unpack('N', substr($$data_ref, $$offset_ref, 4));
    $$offset_ref += 4;
    return $val;
}

sub get_string {
    my ($data_ref, $offset_ref) = @_;
    my $len = get_u32($data_ref, $offset_ref);
    my $str = substr($$data_ref, $$offset_ref, $len);
    my $pad = (4 - ($len % 4)) % 4;
    $$offset_ref += $len + $pad;
    return $str;
}

sub get_bytes {
    my ($data_ref, $offset_ref, $count) = @_;
    my $bytes = substr($$data_ref, $$offset_ref, $count);
    my $pad = (4 - ($count % 4)) % 4;
    $$offset_ref += $count + $pad;
    return $bytes;
}

sub hex_dump {
    my ($data) = @_;
    my $hex = '';
    for my $i (0..length($data)-1) {
        $hex .= sprintf("%02x ", ord(substr($data, $i, 1)));
    }
    return $hex;
}
