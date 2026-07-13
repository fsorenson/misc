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

# MOUNTD procedures
my %mountd_procs = (
    0 => 'NULL',
    1 => 'MNT',
    2 => 'DUMP',
    3 => 'UMNT',
    4 => 'UMNTALL',
    5 => 'EXPORT',
);

# Portmap v2 procedures
my %pmap2_procs = (
    0 => 'NULL',
    1 => 'SET',
    2 => 'UNSET',
    3 => 'GETPORT',
    4 => 'DUMP',
    5 => 'CALLIT',
);

# Portmap v3/v4 (rpcbind) procedures
my %pmap3_procs = (
    0 => 'NULL',
    1 => 'SET',
    2 => 'UNSET',
    3 => 'GETADDR',
    4 => 'DUMP',
    5 => 'CALLIT',
    6 => 'GETTIME',
    7 => 'UADDR2TADDR',
    8 => 'TADDR2UADDR',
    9 => 'GETVERSADDR',
    10 => 'INDIRECT',
    11 => 'GETADDRLIST',
    12 => 'GETSTAT',
);

# Auth flavors
my %auth_flavors = (
    0 => 'AUTH_NULL',
    1 => 'AUTH_UNIX',
    2 => 'AUTH_SHORT',
    3 => 'AUTH_DH',
    6 => 'RPCSEC_GSS',
    0x20000046 => 'AUTH_LOCAL',  # Local Unix socket auth
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
my %call_info = ();  # Track CALL info by XID for correlation with REPLY
my %socket_info = (); # Track socket info: socket_id -> {fd => num, prog => name, etc}

while (my $line = <$in>) {
    # Track socket creation
    if ($line =~ /socket\(.*\) = (\d+)<socket:\[(\d+)\]>/) {
        my ($fd, $socket_id) = ($1, $2);
        $socket_info{$socket_id} = {fd => $fd};
    }

    # Track connections to identify what we're talking to
    if ($line =~ /connect\(\d+<socket:\[(\d+)\]>, \{sa_family=AF_INET, sin_port=htons\((\d+)\)/) {
        my ($socket_id, $port) = ($1, $2);
        if (exists $socket_info{$socket_id}) {
            $socket_info{$socket_id}{port} = $port;
            $socket_info{$socket_id}{service} =
                ($port == 111) ? 'rpcbind' :
                ($port == 2049) ? 'nfs' :
                ($port == 20048) ? 'mountd' :
                "port_$port";
        }
    }

    # Parse write() - outgoing packet
    if ($line =~ /(\d+):(\d+):(\d+)\.(\d+).*write\((\d+)<socket:\[(\d+)\]>, "((?:\\x[0-9a-fA-F]{2})+)"/) {
        my ($h, $m, $s, $us, $fd, $socket_id, $hex_data) = ($1, $2, $3, $4, $5, $6, $7);
        my $timestamp = sprintf("%02d:%02d:%02d.%06d", $h, $m, $s, $us);
        my $data = parse_hex($hex_data);

        my $service = $socket_info{$socket_id}{service} || "unknown";

        print "=" x 70 . "\n";
        print "Packet #" . ++$packet_num . " [$timestamp] CALL (write to $service)\n";
        print "=" x 70 . "\n";

        my ($prog, $vers, $proc, $xid) = decode_rpc($data, 'CALL');
        if (defined $xid) {
            $call_info{$xid} = [$prog, $vers, $proc];
        }
        print "\n";
    }
    # Parse read() - incoming packet
    elsif ($line =~ /(\d+):(\d+):(\d+)\.(\d+).*read\((\d+)<socket:\[(\d+)\]>, "((?:\\x[0-9a-fA-F]{2})+)"/) {
        my ($h, $m, $s, $us, $fd, $socket_id, $hex_data) = ($1, $2, $3, $4, $5, $6, $7);
        my $timestamp = sprintf("%02d:%02d:%02d.%06d", $h, $m, $s, $us);
        my $data = parse_hex($hex_data);

        my $service = $socket_info{$socket_id}{service} || "unknown";

        print "=" x 70 . "\n";
        print "Packet #" . ++$packet_num . " [$timestamp] REPLY (read from $service)\n";
        print "=" x 70 . "\n";

        decode_rpc($data, 'REPLY', \%call_info);
        print "\n";
    }
}

close($in);

# Parse hex string like "\x80\x00\x01\x23" to binary data
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
    my ($data, $direction, $call_info_ref) = @_;
    my $offset = 0;

    # Check for record marker (TCP/Unix socket framing)
    if (length($data) >= 4) {
        my $marker = get_u32(\$data, \$offset);
        my $last_frag = ($marker & 0x80000000) ? 1 : 0;
        my $frag_len = $marker & 0x7fffffff;

        print "RPC Record Marker:\n";
        print "  Last Fragment: " . ($last_frag ? "YES" : "NO") . "\n";
        print "  Fragment Length: $frag_len bytes\n";
        print "\n";
    }

    # RPC message header
    my $xid = get_u32(\$data, \$offset);
    my $msg_type = get_u32(\$data, \$offset);

    print "RPC Header:\n";
    print "  XID: 0x" . sprintf("%08x", $xid) . " ($xid)\n";
    print "  Message Type: " . ($msg_type == 0 ? "CALL" : "REPLY") . " ($msg_type)\n";

    if ($msg_type == 0) {
        my ($prog, $vers, $proc) = decode_call(\$data, \$offset);
        return ($prog, $vers, $proc, $xid);
    } else {
        decode_reply(\$data, \$offset, $xid, $call_info_ref);
        return ();
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
    my $proc_name;
    if ($prog == 100000) {
        # Portmapper/rpcbind
        $proc_name = ($vers == 3 || $vers == 4) ?
                     ($pmap3_procs{$proc} || "UNKNOWN") :
                     ($pmap2_procs{$proc} || "UNKNOWN");
    } elsif ($prog == 100005) {
        # MOUNTD
        $proc_name = $mountd_procs{$proc} || "UNKNOWN";
    } else {
        $proc_name = $proc;
    }

    print "  RPC Version: $rpc_vers\n";
    print "  Program: $prog ($prog_name)\n";
    print "  Program Version: $vers\n";
    print "  Procedure: $proc ($proc_name)\n";
    print "\n";

    # Decode credentials
    print "Credentials:\n";
    decode_auth($data_ref, $offset_ref);
    print "\n";

    # Decode verifier
    print "Verifier:\n";
    decode_auth($data_ref, $offset_ref);
    print "\n";

    # Decode procedure-specific parameters
    if ($prog == 100000) {
        decode_portmap_call($data_ref, $offset_ref, $vers, $proc);
    } elsif ($prog == 100005) {
        decode_mountd_call($data_ref, $offset_ref, $vers, $proc);
    }

    # Store for reply correlation
    return ($prog, $vers, $proc);
}

# Decode RPC REPLY
sub decode_reply {
    my ($data_ref, $offset_ref, $xid, $call_info_ref) = @_;

    my $reply_state = get_u32($data_ref, $offset_ref);

    print "  Reply State: " . ($reply_state == 0 ? "MSG_ACCEPTED" : "MSG_DENIED") . " ($reply_state)\n";

    if ($reply_state == 0) {
        # Message accepted
        print "\n";
        print "Verifier:\n";
        decode_auth($data_ref, $offset_ref);
        print "\n";

        my $accept_state = get_u32($data_ref, $offset_ref);
        my $accept_name = $accept_states{$accept_state} || "UNKNOWN";
        print "Accept State: $accept_state ($accept_name)\n";

        if ($accept_state == 0 && $$offset_ref < length($$data_ref)) {
            print "\n";
            # Get original CALL info for this XID
            my ($prog, $vers, $proc) = (0, 0, 0);
            if ($call_info_ref && exists $call_info_ref->{$xid}) {
                ($prog, $vers, $proc) = @{$call_info_ref->{$xid}};
            }

            if ($prog == 100000) {
                decode_portmap_reply($data_ref, $offset_ref, $proc, $vers);
            } elsif ($prog == 100005) {
                decode_mountd_reply($data_ref, $offset_ref, $proc, $vers);
            } else {
                # Generic reply - just show hex
                if ($$offset_ref < length($$data_ref)) {
                    my $remaining = substr($$data_ref, $$offset_ref);
                    print "Reply Data:\n";
                    print "  " . hex_dump($remaining) . "\n";
                }
            }
        }
    } else {
        # Message denied
        my $reject_state = get_u32($data_ref, $offset_ref);
        print "  Reject State: $reject_state\n";
    }
}

# Decode authentication info
sub decode_auth {
    my ($data_ref, $offset_ref) = @_;

    my $flavor = get_u32($data_ref, $offset_ref);
    my $length = get_u32($data_ref, $offset_ref);

    my $flavor_name = $auth_flavors{$flavor} || sprintf("UNKNOWN(0x%08x)", $flavor);
    print "  Flavor: $flavor_name ($flavor)\n";
    print "  Length: $length bytes\n";

    if ($length > 0) {
        # Read auth data
        my $auth_data = get_bytes($data_ref, $offset_ref, $length);

        if ($flavor == 1) {
            # AUTH_UNIX
            decode_auth_unix(\$auth_data);
        } elsif ($flavor == 0x20000046) {
            # AUTH_LOCAL (Unix socket specific)
            decode_auth_local(\$auth_data);
        } else {
            # Generic hex dump
            print "  Data: " . hex_dump($auth_data) . "\n";
        }
    }
}

# Decode AUTH_UNIX credentials
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

# Decode AUTH_LOCAL credentials
sub decode_auth_local {
    my ($data_ref) = @_;
    print "  Data (hex): " . hex_dump($$data_ref) . "\n";
}

# Decode portmap CALL parameters
sub decode_portmap_call {
    my ($data_ref, $offset_ref, $vers, $proc) = @_;

    print "Portmap Parameters:\n";

    if ($proc == 1) {
        # SET
        decode_pmap_mapping($data_ref, $offset_ref, $vers);
    } elsif ($proc == 2) {
        # UNSET
        decode_pmap_mapping($data_ref, $offset_ref, $vers);
    } elsif ($proc == 3) {
        # GETPORT (v2) or GETADDR (v3)
        decode_pmap_mapping($data_ref, $offset_ref, $vers);
    } elsif ($proc == 4) {
        # DUMP - no parameters
        print "  (no parameters for DUMP)\n";
    } elsif ($proc == 5) {
        # CALLIT
        decode_pmap_callit($data_ref, $offset_ref, $vers);
    } else {
        # Unknown - show hex
        if ($$offset_ref < length($$data_ref)) {
            my $remaining = substr($$data_ref, $$offset_ref);
            print "  Raw data: " . hex_dump($remaining) . "\n";
        }
    }
}

# Decode portmap REPLY
sub decode_portmap_reply {
    my ($data_ref, $offset_ref, $proc, $vers) = @_;

    print "Portmap Reply:\n";

    if ($$offset_ref >= length($$data_ref)) {
        print "  (empty - boolean FALSE or NULL result)\n";
        return;
    }

    if ($proc == 4) {
        # DUMP - list of mappings
        decode_pmap_dump_reply($data_ref, $offset_ref, $vers);
    } elsif ($proc == 12) {
        # GETSTAT - rpcbind statistics
        decode_pmap_getstat_reply($data_ref, $offset_ref);
    } elsif ($proc == 3) {
        # GETPORT/GETADDR - returns port number or address string
        if ($vers == 2) {
            my $port = get_u32($data_ref, $offset_ref);
            print "  Port: $port\n";
        } else {
            my $addr = get_string($data_ref, $offset_ref);
            print "  Address: '$addr'\n";
        }
    } else {
        # For most portmap calls (SET, UNSET), reply is a boolean
        my $result = get_u32($data_ref, $offset_ref);
        my $bool_str = ($result == 1) ? "TRUE (success)" :
                       ($result == 0) ? "FALSE (not found/failed)" :
                       "UNKNOWN";
        print "  Result: $result ($bool_str)\n";

        # If there's more data, show it
        if ($$offset_ref < length($$data_ref)) {
            my $remaining = substr($$data_ref, $$offset_ref);
            print "  Additional data: " . hex_dump($remaining) . "\n";
        }
    }
}

# Decode portmap mapping structure
sub decode_pmap_mapping {
    my ($data_ref, $offset_ref, $vers) = @_;

    my $prog = get_u32($data_ref, $offset_ref);
    my $prog_vers = get_u32($data_ref, $offset_ref);

    my $prog_name = $programs{$prog} || "UNKNOWN";
    print "  Program: $prog ($prog_name)\n";
    print "  Version: $prog_vers\n";

    if ($vers == 2) {
        # Portmap v2 - uses protocol number and port
        if ($$offset_ref < length($$data_ref)) {
            my $protocol = get_u32($data_ref, $offset_ref);
            my $port = get_u32($data_ref, $offset_ref);
            print "  Protocol: $protocol (" . ($protocol == 6 ? "TCP" : $protocol == 17 ? "UDP" : "OTHER") . ")\n";
            print "  Port: $port\n";
        }
    } else {
        # Portmap v3/v4 - uses netid and uaddr strings
        if ($$offset_ref < length($$data_ref)) {
            my $netid = get_string($data_ref, $offset_ref);
            print "  NetID: '$netid'\n";

            if ($$offset_ref < length($$data_ref)) {
                my $uaddr = get_string($data_ref, $offset_ref);
                print "  Universal Address: '$uaddr'\n";
            }

            if ($$offset_ref < length($$data_ref)) {
                my $owner = get_string($data_ref, $offset_ref);
                print "  Owner: '$owner'\n";
            }
        }
    }
}

# Decode DUMP reply - list of registered mappings
sub decode_pmap_dump_reply {
    my ($data_ref, $offset_ref, $vers) = @_;

    my $count = 0;
    print "  Registered Services:\n";

    # DUMP returns a linked list of mappings
    # Each entry: value_follows (bool) + mapping_data
    while ($$offset_ref < length($$data_ref)) {
        my $value_follows = get_u32($data_ref, $offset_ref);

        if (!$value_follows) {
            # End of list
            last;
        }

        $count++;
        print "\n  Entry #$count:\n";

        # Decode mapping
        my $prog = get_u32($data_ref, $offset_ref);
        my $prog_vers = get_u32($data_ref, $offset_ref);
        my $prog_name = $programs{$prog} || "UNKNOWN";

        print "    Program: $prog ($prog_name)\n";
        print "    Version: $prog_vers\n";

        if ($vers == 2) {
            # Portmap v2 - protocol and port
            my $protocol = get_u32($data_ref, $offset_ref);
            my $port = get_u32($data_ref, $offset_ref);
            my $proto_name = ($protocol == 6) ? "TCP" :
                           ($protocol == 17) ? "UDP" : "OTHER";
            print "    Protocol: $protocol ($proto_name)\n";
            print "    Port: $port\n";
        } else {
            # Portmap v3/v4 - netid, uaddr, owner
            my $netid = get_string($data_ref, $offset_ref);
            my $uaddr = get_string($data_ref, $offset_ref);
            my $owner = get_string($data_ref, $offset_ref);

            print "    NetID: '$netid'\n";
            print "    Universal Address: '$uaddr'\n";
            print "    Owner: '$owner'\n";
        }
    }

    if ($count == 0) {
        print "    (no registered services)\n";
    } else {
        print "\n  Total entries: $count\n";
    }
}

# Decode GETSTAT reply - rpcbind statistics
sub decode_pmap_getstat_reply {
    my ($data_ref, $offset_ref) = @_;

    my @proc_names_v2 = qw(NULL SET UNSET GETPORT DUMP CALLIT);
    my @proc_names_v3 = qw(NULL SET UNSET GETADDR DUMP CALLIT TIME U2T T2U);
    my @proc_names_v4_part1 = qw(NULL SET UNSET GETADDR DUMP CALLIT TIME U2T T2U);
    my @proc_names_v4_part2 = qw(VERADDR INDRECT GETLIST GETSTAT);

    print "  Statistics:\n\n";

    # rpcb_stat_byvers is an array of 3 rpcb_stat structures (for RPCBVERS_2_STAT, RPCBVERS_3_STAT, RPCBVERS_4_STAT)
    # The XDR encoding is: [stat_v2] [stat_v3] [stat_v4]
    # Each rpcb_stat contains:
    #   - info[RPCBSTAT_HIGHPROC=13]: procedure call counts (but only first 6/9/13 are used)
    #   - setinfo: int (SET success count)
    #   - unsetinfo: int (UNSET success count)
    #   - addrinfo: rpcbs_addrlist* (linked list)
    #   - rmtinfo: rpcbs_rmtcalllist* (linked list)

    # Decode statistics for each version (2, 3, 4)
    for my $vers_idx (0 .. 2) {
        my $vers = $vers_idx + 2;  # v2, v3, v4

        print "  " . "=" x 70 . "\n";
        if ($vers == 2) {
            print "  PORTMAP (version 2) statistics\n";
        } else {
            print "  RPCBIND (version $vers) statistics\n";
        }
        print "  " . "=" x 70 . "\n";

        # Read info[13] array - always 13 elements, but only some are used
        my @info;
        for my $i (0 .. 12) {
            push @info, get_u32($data_ref, $offset_ref);
        }

        # Read setinfo and unsetinfo
        my $set_success = get_u32($data_ref, $offset_ref);
        my $unset_success = get_u32($data_ref, $offset_ref);

        # Read addrinfo linked list
        my $addr_success = 0;
        my $addr_failure = 0;
        while (1) {
            my $value_follows = get_u32($data_ref, $offset_ref);
            last unless $value_follows;

            my $prog = get_u32($data_ref, $offset_ref);
            my $vers_num = get_u32($data_ref, $offset_ref);
            my $success = get_u32($data_ref, $offset_ref);
            my $failure = get_u32($data_ref, $offset_ref);
            my $netid = get_string($data_ref, $offset_ref);

            $addr_success += $success;
            $addr_failure += $failure;
        }

        # Read rmtinfo linked list
        my $rmt_success = 0;
        my @rmtinfo_list = ();
        while (1) {
            my $value_follows = get_u32($data_ref, $offset_ref);
            last unless $value_follows;

            my %entry = (
                prog => get_u32($data_ref, $offset_ref),
                vers => get_u32($data_ref, $offset_ref),
                proc => get_u32($data_ref, $offset_ref),
                success => get_u32($data_ref, $offset_ref),
                failure => get_u32($data_ref, $offset_ref),
                indirect => get_u32($data_ref, $offset_ref),
                netid => get_string($data_ref, $offset_ref),
            );

            $rmt_success += $entry{success};
            push @rmtinfo_list, \%entry;
        }

        # Print procedure statistics - first row
        my @names_row1 = ($vers == 2) ? @proc_names_v2 :
                         ($vers == 3) ? @proc_names_v3 : @proc_names_v4_part1;

        print "  ";
        for my $i (0 .. $#names_row1) {
            printf "%-8s", $names_row1[$i];
        }
        print "\n  ";

        for my $i (0 .. $#names_row1) {
            my $name = $names_row1[$i];
            if ($name eq 'SET') {
                # Format is success/total (not success/failure)
                printf "%-8s", "$set_success/$info[$i]";
            } elsif ($name eq 'UNSET') {
                # Format is success/total (not success/failure)
                printf "%-8s", "$unset_success/$info[$i]";
            } elsif ($name eq 'GETPORT' || $name eq 'GETADDR') {
                printf "%-8s", "$addr_success/$addr_failure";
            } elsif ($name eq 'CALLIT') {
                printf "%-8s", "$rmt_success/$info[$i]";
            } else {
                printf "%-8d", $info[$i];
            }
        }
        print "\n";

        # For version 4, print second row of procedures
        if ($vers == 4) {
            print "  ";
            for my $i (0 .. $#proc_names_v4_part2) {
                printf "%-8s", $proc_names_v4_part2[$i];
            }
            print "\n  ";
            for my $i (9 .. 12) {
                printf "%-8d", $info[$i];
            }
            print "\n";
        }

        # Print rmtinfo (remote call statistics)
        print "\n";
        if ($vers == 2) {
            print "  PMAP_RMTCALL call statistics\n";
        } else {
            print "  RPCB_RMTCALL (version $vers) call statistics\n";
        }
        print "  " . "-" x 70 . "\n";
        printf "  %-15s %-7s %-7s %-7s %-9s %-9s\n",
               "prog", "vers", "proc", "netid", "success", "failure";

        if (@rmtinfo_list) {
            for my $entry (@rmtinfo_list) {
                my $prog_name = $programs{$entry->{prog}} || $entry->{prog};
                printf "  %-15s %-7d %-7d %-7s %-9d %-9d\n",
                       $prog_name, $entry->{vers}, $entry->{proc}, $entry->{netid},
                       $entry->{success}, $entry->{failure};
            }
        } else {
            print "  (no remote call statistics)\n";
        }

        print "\n";
    }
}

# Decode CALLIT parameters
sub decode_pmap_callit {
    my ($data_ref, $offset_ref, $vers) = @_;

    my $prog = get_u32($data_ref, $offset_ref);
    my $prog_vers = get_u32($data_ref, $offset_ref);
    my $proc = get_u32($data_ref, $offset_ref);

    my $prog_name = $programs{$prog} || "UNKNOWN";
    print "  Program: $prog ($prog_name)\n";
    print "  Version: $prog_vers\n";
    print "  Procedure: $proc\n";

    # Arguments (opaque data)
    if ($$offset_ref < length($$data_ref)) {
        my $args_len = get_u32($data_ref, $offset_ref);
        print "  Arguments Length: $args_len bytes\n";
        if ($args_len > 0) {
            my $args = get_bytes($data_ref, $offset_ref, $args_len);
            print "  Arguments (hex): " . hex_dump($args) . "\n";
        }
    }
}

# Decode MOUNTD CALL parameters
sub decode_mountd_call {
    my ($data_ref, $offset_ref, $vers, $proc) = @_;

    print "MOUNTD Parameters:\n";

    if ($proc == 1) {
        # MNT - mount request
        my $dirpath = get_string($data_ref, $offset_ref);
        print "  Directory: '$dirpath'\n";
    } elsif ($proc == 3) {
        # UMNT - unmount request
        my $dirpath = get_string($data_ref, $offset_ref);
        print "  Directory: '$dirpath'\n";
    } elsif ($proc == 5) {
        # EXPORT - no parameters
        print "  (no parameters for EXPORT)\n";
    } elsif ($proc == 0) {
        # NULL - no parameters
        print "  (no parameters for NULL)\n";
    } else {
        # Unknown - show hex
        if ($$offset_ref < length($$data_ref)) {
            my $remaining = substr($$data_ref, $$offset_ref);
            print "  Raw data: " . hex_dump($remaining) . "\n";
        }
    }
}

# Decode MOUNTD REPLY
sub decode_mountd_reply {
    my ($data_ref, $offset_ref, $proc, $vers) = @_;

    print "MOUNTD Reply:\n";

    if ($proc == 5) {
        # EXPORT - list of exports
        decode_exports_list($data_ref, $offset_ref);
    } elsif ($proc == 1) {
        # MNT - mount reply with file handle
        my $status = get_u32($data_ref, $offset_ref);
        print "  Status: $status\n";
        if ($status == 0 && $$offset_ref < length($$data_ref)) {
            # File handle
            my $fh_len = get_u32($data_ref, $offset_ref);
            if ($fh_len > 0) {
                my $fh = substr($$data_ref, $$offset_ref, $fh_len);
                $$offset_ref += $fh_len;
                print "  File Handle (" . $fh_len . " bytes): " . hex_dump($fh) . "\n";
            }
        }
    } elsif ($proc == 2) {
        # DUMP - list of mounted directories
        decode_mount_list($data_ref, $offset_ref);
    } else {
        # Generic reply
        if ($$offset_ref < length($$data_ref)) {
            my $remaining = substr($$data_ref, $$offset_ref);
            print "  Data: " . hex_dump($remaining) . "\n";
        }
    }
}

# Decode EXPORT reply (linked list of exports)
sub decode_exports_list {
    my ($data_ref, $offset_ref) = @_;

    print "  Exported directories:\n";

    my $count = 0;
    while ($$offset_ref < length($$data_ref)) {
        my $value_follows = get_u32($data_ref, $offset_ref);
        last unless $value_follows;

        $count++;
        my $dir = get_string($data_ref, $offset_ref);
        print "\n  Export #$count:\n";
        print "    Directory: $dir\n";

        # Read groups (linked list of hostnames/groups that can mount)
        print "    Groups:\n";
        my $group_count = 0;
        while ($$offset_ref < length($$data_ref)) {
            my $group_follows = get_u32($data_ref, $offset_ref);
            last unless $group_follows;

            $group_count++;
            my $group = get_string($data_ref, $offset_ref);
            print "      $group\n";
        }
        if ($group_count == 0) {
            print "      (everyone)\n";
        }
    }

    if ($count == 0) {
        print "    (no exports)\n";
    } else {
        print "\n  Total exports: $count\n";
    }
}

# Decode mount list (linked list of mounted directories)
sub decode_mount_list {
    my ($data_ref, $offset_ref) = @_;

    print "  Mounted directories:\n";

    my $count = 0;
    while ($$offset_ref < length($$data_ref)) {
        my $value_follows = get_u32($data_ref, $offset_ref);
        last unless $value_follows;

        $count++;
        my $hostname = get_string($data_ref, $offset_ref);
        my $directory = get_string($data_ref, $offset_ref);

        print "    $hostname:$directory\n";
    }

    if ($count == 0) {
        print "    (no mounts)\n";
    }
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
