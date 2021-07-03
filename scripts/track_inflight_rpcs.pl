#!/usr/bin/perl -w

use warnings;
use strict;

if (scalar(@ARGV) != 1) {
	printf("usage: %s <pcap_filename>\n", $0);
	exit 1;
}
my $filename = $ARGV[0];

my $DEBUG = 0;

my %inflight_xids = ();
my %tcp_connections = ();
my %max_inflight = ();

sub trim {
	my $str = shift;
	$str =~ s/^\s|\s+$//g;
	return $str;
}

sub tcp_conn_str {
	my ($ip1, $port1, $ip2, $port2, $msgtyp) = @_;

	return sprintf("%s:%s - %s:%s", $ip1, $port1, $ip2, $port2) if ($msgtyp == 0);
	return sprintf("%s:%s - %s:%s", $ip2, $port2, $ip1, $port1) if ($msgtyp == 1);
	printf("invalid rpc.msgtyp: %s\n", $msgtyp);
	die();
}

my $cmd = "tshark -n -Tfields -E header=n -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e rpc.msgtyp -e rpc.xid -r " . $filename . " 'rpc.xid'";
#4	168.94.15.4	9315	172.16.209.31	2049	0,0,0,0,0,0,0	0xfe796ad8,0xfe796ad9,0xfe796ada,0xfe796adb,0xfe796adc,0xfe796add,0xfe796ade
#5	168.94.15.4	9315	172.16.209.31	2049	0,0,0,0,0,0,0,0	0xfe796adf,0xfe796ae0,0xfe796ae1,0xfe796ae2,0xfe796ae3,0xfe796ae4,0xfe796ae5,0xfe796ae6
#9	168.94.15.4	9315	172.16.209.31	2049	0	0xfe796ae7
#15	168.94.15.4	60688	172.16.209.31	2049	0,0,0,0,0,0,0	0xfe796ae9,0xfe796aea,0xfe796aeb,0xfe796aec,0xfe796aed,0xfe796aee,0xfe796aef
#16	168.94.15.4	60688	172.16.209.31	2049	0,0,0,0,0,0,0,0	0xfe796af0,0xfe796af1,0xfe796af2,0xfe796af3,0xfe796af4,0xfe796af5,0xfe796af6,0xfe796af7
#23	168.94.15.4	60688	172.16.209.31	2049	0	0xfe796af8
#42	172.16.209.31	2049	168.94.15.4	60688	1	0xfe796aea

my $ip_octet_pat = "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";
my $ip_pat = "(?:(?:$ip_octet_pat\.){3}(?:$ip_octet_pat))";
my $msgtyp_pat = "(?:(?:[01](?:,[01])*))";
my $xid_pat = "(?:(0x(?:[0-9a-f]){8}(?:,0x[0-9a-f]{8})*))";

my $re = qr/^(\d+)\s+($ip_pat)\s+(\d+)\s+($ip_pat)\s+(\d+)\s+($msgtyp_pat)\s+($xid_pat)$/;


printf("executing commaand: %s\n", $cmd) if ($DEBUG >= 1);
open (PCAP, "$cmd|") or die("Failed to exec tshark command \"$cmd\": $!");

while (<PCAP>) {
	my $line = trim($_);

	if (my ($frame, $srcip, $srcport, $dstip, $dstport, $msgtyp_str, $xids_str) = $line =~ $re) {
		my @msgtyps = split(",", $msgtyp_str);
		my @xids = split(",", $xids_str);

		my $conn_str = tcp_conn_str($srcip, $srcport, $dstip, $dstport, $msgtyps[0]);

		if ($msgtyps[0] == 0) {
			printf("frame %d: %s call, %d xids\n", $frame, $conn_str, scalar @xids) if ($DEBUG >= 1);
			foreach my $xid (@xids) {
				printf("  call xid: %s\n", $xid) if ($DEBUG >= 2);
				$inflight_xids{$conn_str}{$xid} = 1;
			}
		} else {
			printf("frame %d: %s reply, %d xids\n", $frame, $conn_str, scalar @xids) if ($DEBUG >= 1);
			foreach my $xid (@xids) {
				printf("  reply xid: %s\n", $xid) if ($DEBUG >= 2);
				delete $inflight_xids{$conn_str}{$xid} if (defined($inflight_xids{$conn_str}{$xid}));
			}
		}

		my $current_inflight = scalar(keys %{$inflight_xids{$conn_str}});
		$max_inflight{$conn_str} = $current_inflight if ((!defined($max_inflight{$conn_str})) or $current_inflight > $max_inflight{$conn_str});

		printf("frame %d - $conn_str  current in-flight: %d; max in-flight: %d\n", $frame, $current_inflight, $max_inflight{$conn_str});
	} else {
		printf("didn't match regex for '%s'\n", $line);
	}
}

while (my ($conn_str, $v) = each %max_inflight) {
	printf(" max inflight for %s: %d\n", $conn_str, $max_inflight{$conn_str});
}
