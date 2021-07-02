#!/usr/bin/perl -w

use warnings;
use strict;

my $DEBUG = 0;

if (scalar(@ARGV) != 1) {
	printf("usage: %s <pcap_filename>\n", $0);
	exit 1;
}
my $filename = $ARGV[0];

my %inflight_xids = ();
my $max_inflight = 0;

sub trim {
	my $str = shift;
	$str =~ s/^\s|\s+$//g;
	return $str;
}

my $re = qr/^([0-9]+)\s+([01](?:,[01])*)\s(0x(?:[0-9a-f]){8}(?:,0x[0-9a-f]{8})*)$/;

my $cmd = "tshark -n -Tfields -E header=n -e frame.number -e rpc.msgtyp -e rpc.xid -r " . $filename . " 'rpc && rpc.msgtyp'";

printf("executing commaand: %s\n", $cmd) if ($DEBUG >= 1);
open (PCAP, "$cmd|") or die("Failed to exec tshark command \"$cmd\": $!");

while (<PCAP>) {
	my $line = trim($_);

	if (my ($frame, $msgtyp_str, $xids_str) = $line =~ $re) {
		my @msgtyps = split(",", $msgtyp_str);
		my @xids = split(",", $xids_str);

		if ($msgtyps[0] == 0) {
			printf("frame %d: call\n") if ($DEBUG >= 1);
			foreach my $xid (@xids) {
				printf("  call xid: %s\n", $xid) if ($DEBUG >= 2);
				$inflight_xids{$xid} = 1;
			}
		} else {
			printf("frame %d: reply\n") if ($DEBUG >= 1);
			foreach my $xid (@xids) {
				printf("  reply xid: %s\n", $xid) if ($DEBUG >= 2);
				delete $inflight_xids{$xid} if (defined($inflight_xids{$xid}));
			}
		}
		my $current_inflight = scalar(values %inflight_xids);
		$max_inflight = $current_inflight if ($current_inflight > $max_inflight);
		printf("frame %d - current in-flight: %d; max in-flight: %d\n", $frame, $current_inflight, $max_inflight);
	} else {
		printf("didn't match regex for '%s'\n", $line);
	}
}
printf("max in-flight %d\n", $max_inflight);
