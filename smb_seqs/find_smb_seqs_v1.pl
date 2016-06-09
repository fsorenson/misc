#!/usr/bin/perl -w

# Frank Sorenson <sorenson@redhat.com>
# Red Hat, 2016
#
# script to find cifs sequence matching the signature from the packet
# requires the wireshark patch exposing the cifs.payload

use strict;
use Digest::MD5 qw(md5 md5_hex md5_base64);

my $backtrack = 8;

my $in;
my $pcap_filename;
my $session_key;


# unbuffer
select STDOUT; $| = 1;

if ($#ARGV == 1) { # session key
	$pcap_filename = $ARGV[0];
	$session_key = hex_bin $ARGV[1];
} else {
	printf "Usage: dump_smb_v0.2 <packet_dump.pcap> <session_key>\n";
	exit;
}

sub hex_bin {
	my $str = shift;
	return join "", map{pack('C', hex($_)) } ($str =~ /(..)/g);
}

sub get_sig {
	my ($msg, $skey, $seq) = @_;

	my $ctx = Digest::MD5->new;

	$ctx->add($session_key);
	$ctx->add(substr($msg, 0, 14));
	$ctx->add(pack('Q', $seq));

	$ctx->add(substr($msg, 22));
	return substr($ctx->digest, 0, 8);
}

sub get_sig_hex {
	my ($msg, $skey, $seq) = @_;

	my $ctx = Digest::MD5->new;

	$ctx->add($session_key);
	$ctx->add(substr($msg, 0, 14));
	$ctx->add(pack('Q', $seq));

	$ctx->add(substr($msg, 22));
	return substr($ctx->hexdigest, 0, 16);
}

sub test_sig {
	my ($msg, $skey, $seq) = @_;

	my $orig_sig = substr($msg, 14, 8);

	my $ret = get_sig($msg, $skey, $seq);
	return ($orig_sig eq $ret);
}

sub search_seq {
	my $hint = 0;
	my ($msg, $skey) = @_;
	if (scalar @_ == 0) {
		$hint = shift;
		if ($hint > $backtrack) { $hint -= $backtrack; }
		else { $hint = 0; }
	}

	my $orig_sig = substr($msg, 14, 8);

	for (my $seq = $hint ; $seq < 0xFFFFFFFF ; $seq ++) {
		my $ret = get_sig($msg, $skey, $seq);
		return $seq if ($orig_sig eq $ret);
	}
	for (my $seq = 0 ; $seq < $hint ; $seq ++) {
		my $ret = get_sig($msg, $skey, $seq);
		return $seq if ($orig_sig eq $ret);
	}

	return undef;
}


my @tshark_fields = ( 'frame.number', '_ws.col.Info', 'smb.mid', 'smb.cmd',
	'smb.signature', 'smb.session_key', 'smb.payload_len', 'smb.payload');

my $cmd = "tshark -2 -O smb.raw_payload:TRUE -E header=y -E quote=d -E separator=\\; -T fields";
foreach my $f (@tshark_fields) { $cmd .= " -e $f"; }
$cmd .= " -r $pcap_filename 'smb'";

printf "command is %s\n", $cmd;

open($in, "$cmd |");
my $fields_string = <$in>;
$fields_string =~ s/^\s|\s$//g;

my @fields = split(";", $fields_string);
my $field_count = scalar @fields;
my $last_seq = 0;

while (my $line = <$in>) {
	my %frame_info;
	$line =~ s/^\s|\s$//g;

	my @frame_fields = split(";", $line);
	for (my $i = 0 ; $i < $field_count ; $i ++) {
		my $value = $frame_fields[$i];
		$value =~ s/^\"|\"$//g; # strip off the quotes
		my $field_name = $fields[$i];

		$frame_info{$field_name} = $value;
	}

	printf "Frame %d - ", $frame_info{'frame.number'};
	printf "%s\n", $frame_info{'_ws.col.Info'};

	my @cmds = split(",", $frame_info{'smb.cmd'});
	my @mids = split(",", $frame_info{'smb.mid'});
	my @sigs = split(",", $frame_info{'smb.signature'});
	my @payload_lengths = split(",", $frame_info{'smb.payload_len'});
	my @payloads = split(",", $frame_info{'smb.payload'});

	my $mid_count = scalar @mids;

	for (my $i = 0 ; $i < $mid_count ; $i ++) {
		printf "\tmid: %d\n", $mids[$i];
		printf "\t\tsignature: %s\n", $sigs[$i];
		printf "\t\tpayload_len: %d\n", $payload_lengths[$i];

#		printf "\t\tpayload: %s\n", $payloads[$i];
		my $cpay = hex_bin $payloads[$i];

		my $seq = search_seq($cpay, $session_key, $last_seq);
		if (defined $seq) {
			printf "\t\tsequence: %d\n", $seq;
			$last_seq = $seq;
		} else {
			printf "\t\tsequence: UNKNOWN\n";
		}
	}
	if (!($frame_info{'smb.session_key'} =~ /^\s*$/)) {
		# if we didn't have the session key, we should be able to set it from this
		printf "\t\tsession key: %s\n", $frame_info{'smb.session_key'};
	}
}
