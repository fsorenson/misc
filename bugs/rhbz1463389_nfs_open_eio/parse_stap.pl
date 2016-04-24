#!/usr/bin/perl -w

# Frank Sorenson <sorenson@redhat.com>, 2016

# usage:
# ./parse_stap.pl stap.log | text2pcap -T 2049,1500 -t '%s.' -Dn - out.pcap
#
# note:  expects to read in the stap output from nfs_open_dump.stap ... may need modification for use with other output
#
# (you can cat the log parts together to create a single input file, if desired)
#
# pardon my perl

use strict;
use DateTime::Format::Strptime;
import DateTime::Format::Strptime qw(strftime);

local $/ = undef;
open FILE, $ARGV[0] or die "couldn't open file: $!";

my $data = <FILE>;

$data =~ s/probe started\n//g;

my $last_date = 0.0;

# ignore 'nfs4_open_done'
$data =~ s/([^\n]*) nfs4_open_done ([^\n]+)\n//g;

while ($data =~ m/(.+?) nfs4_xdr_dec_open([^\n]+)\n( [^\n]+)\n ([^\n]+)\n/gs) {
	my $date = $1;
	# $2 is remainder of nfs4_xdr_dec_open line
	my $line1 = $3;
	my $line2 = $4;

	if ($line1 =~ /(( [0-9a-f]{2}){4})(( [0-9a-f]{2}){4})(( [0-9a-f]{2}){4})/) {
		my $frag_hdr = $1; # includes size
		my $xid = $3;
		my $hdr_len = 4+4+4+8+4; # leave off the 4-byte frag_hdr

		my $strp = DateTime::Format::Strptime->new(
			pattern => '%a %b %d %H:%M:%S %Y' );
		my $dt = $strp->parse_datetime($date);
		$date = strftime('%s.000000', $dt) + 0.0;

		while ($date <= $last_date) {
			$date += 0.000001;
		}

		printf "o %.06f  00000  $line1\n", $date;

		### now figure out what to add to $line2
		my $len = $hdr_len + (length($line2) + 1)/3;
		my $frag_hdr_val = sprintf "%.8x", $len | 0x80000000;
		my $frag_hdr_str = $frag_hdr_val =~ s/([0-9a-f]{2})/ $1/rg;

		my $out = $frag_hdr_str . $xid . " 00"x3 . " 01" . " 00"x16;

		$date += 0.000001;

		printf "i %.06f  00000  $out $line2\n", $date;

		$last_date = $date;
	}
# 80 00 00 f4 98 09 2f dd 00 00 00 00 00 00 00 02 00 01 86 a3 00 00 00 04 00 00 00 01 00 00 00 01 00 00 00 24 00 c5 19 bc 00 00 00 07 52 48 45 4c 31 36 32 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 01 e6 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 05 00 00 00 16 00 00 00 18 01 00 00 01 00 fd 00 00 0a 00 00 00 e2 03 00 00 df 31 52 12 00 00 00 00 00 00 00 12 00 00 00 00 00 00 00 03 00 00 00 00 78 4d 9c 56 08 00 00 00 00 00 00 14 6f 70 65 6e 20 69 64 3a 00 00 00 20 0e 9c 87 c4 6d 9c d2 18 00 00 00 01 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 04 00 00 01 80 00 00 00 00 00 00 00 09 74 65 73 74 66 69 6c 65 31 00 00 00 00 00 00 0a 00 00 00 03 00 00 00 2d 00 00 00 09 00 00 00 02 00 10 01 1a 00 30 a2 3a

# 00 00 00 00 00 00 00 00 00 00 00 05 00 00 00 16 00 00 00 00 00 00 00 12 00 00 00 00 00 00 00 00 78 4d 9c 56 09 00 00 00 d2 04 00 00 01 00 00 00 c4 59 a0 56 f0 e0 43 2c c6 59 a0 56 20 93 0f 06 00 00 00 06 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 0a 00 00 00 00 00 00 00 18 01 00 00 01 00 fd 00 00 0a 00 00 00 de 04 00 00 af 0f 06 25 00 00 00 00 00 00 00 03 00 00 00 00 00 00 00 2d 00 00 00 0d 00 00 00 09 00 00 00 00 00 00 00 02 00 10 01 1a 00 30 a2 3a 00 00 00 78 00 00 00 01 c6 59 a0 56 c8 77 0f 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 fd 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 de 00 00 01 80 00 00 00 01 00 00 00 01 30 00 00 00 00 00 00 01 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 56 a0 59 c6 06 0f 77 c8 00 00 00 00 56 a0 59 c6 06 0f 77 c8 00 00 00 00 56 a0 59 c6 06 0f 77 c8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

}
#call:  800000dc 0b1b5c11 00000000 00000002000186a300000004000000010000000100000024005c8b92000000075248454c3136330000000000000000000000000200000000000001e60000000000000000
#reply: 80000130 0b1b5c11 00000001 00000000 0000000000000000 00000000
#       |        |        |        |        |                ^accept state (rpc successful=0)
#       |        |        |        |        ^verifier
#       |        |        |        ^reply state (accepted=0)
#       |        |        ^message type (call=0, reply=1)
#       |        ^xid
#       ^frag hdr

#call:  800000dc0c1b5c110000000000000002000186a300000004000000010000000100000024005c8b92000000075248454c3136330000000000000000000000000200000000000001e60000000000000000
#reply: 800001300c1b5c110000000100000000000000000000000000000000

#call:  800000dc0f1b5c110000000000000002000186a300000004000000010000000100000024005c8b92000000075248454c3136330000000000000000000000000200000000000001e60000000000000000
#reply: 800001300f1b5c110000000100000000000000000000000000000000

#call:  800000dc111b5c110000000000000002000186a300000004000000010000000100000024005c8b92000000075248454c3136330000000000000000000000000200000000000001e60000000000000000
#reply: 80000130111b5c110000000100000000000000000000000000000000
