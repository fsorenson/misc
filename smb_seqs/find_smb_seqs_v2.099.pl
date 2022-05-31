#!/usr/bin/perl -w

# Frank Sorenson <sorenson@redhat.com>
# Red Hat, 2016
#
# script to find cifs sequence matching the signature from the packet
# requires the wireshark patch exposing the cifs.payload

use strict;
#use Digest::MD5 qw(md5 md5_hex md5_base64);
use Digest::SHA qw(sha256 hmac_sha256 hmac_sha256_hex sha512 hmac_sha512 hmac_sha512_hex);

my $backtrack = 8;

my $in;
my $pcap_filename;
my $session_key;


# unbuffer
select STDOUT; $| = 1;

sub hex_bin {
	my $str = shift;
	return join "", map{pack('C', hex($_)) } ($str =~ /(..)/g);
}

if ($#ARGV == 1) { # session key
	$pcap_filename = $ARGV[0];
	$session_key = hex_bin $ARGV[1];
} else {
	printf "Usage: dump_smb_v0.2 <packet_dump.pcap> <session_key>\n";
	exit;
}


sub fmt_hex_string {
	my $val = shift;
	my $ret = '';
#	foreach my $char (split //, $@[0]) {
#	foreach my $char (split //, ord($val)) {
	for my $i (0..length($val) - 1) {
		my $char = ord substr($val, $i, 1);
		$ret .= sprintf "%02x", $char;
	}
	return $ret;
}

our $SMB2_HDR_SESSION_ID = 0x28;
our $SMB2_HDR_SIGNATURE = 0x30;
sub get_sig0 {
	my ($msg, $skey, $seq) = @_;

	my $ctx = Digest::SHA->new(256);

#define SMB2_HDR_SESSION_ID	0x28
#define SMB2_HDR_SIGNATURE 0x30
	my $session_id = substr($msg, $SMB2_HDR_SESSION_ID, 8); # 64-bit session_id

	my $orig_sig = substr($msg, $SMB2_HDR_SIGNATURE, 16);

#	$msg = substr($msg, 0, $SMB2_HDR_SIGNATURE) . '\0'x16 . substr($msg, $SMB2_HDR_SIGNATURE + 16);

$ctx->add(substr($msg, 0, $SMB2_HDR_SIGNATURE));
$ctx->add('\0'x16);
$ctx->add(substr($msg, $SMB2_HDR_SIGNATURE + 16));


#	$ctx->add($session_key);
#	$ctx->add(substr($msg, 0, 14));
#	$ctx->add(pack('Q', $seq));
#	$ctx->add(substr($msg, 22));

	return substr($ctx->digest, 0, 8);
}
sub get_sig1 {
	my ($msg, $skey, $seq) = @_;

	my $session_id = substr($msg, $SMB2_HDR_SESSION_ID, 8); # 64-bit session_id
	my $orig_sig = substr($msg, $SMB2_HDR_SIGNATURE, 16);
#	my $new_msg = substr($msg, 0, $SMB2_HDR_SIGNATURE) . '\0'x16 . substr($msg, $SMB2_HDR_SIGNATURE + 16);
	my $new_msg = substr($msg, 0, $SMB2_HDR_SIGNATURE) . chr(0)x16 . substr($msg, $SMB2_HDR_SIGNATURE + 16);

	#printf "session id: %d\n", $session_id;
	printf "session id: %s\n", fmt_hex_string($session_id);

printf "new message is %d bytes: %s\n", length($new_msg), fmt_hex_string($new_msg);

	my $thing = substr(hmac_sha256($new_msg, $skey), 0, 16);
#	my $thing_hex = hmac_sha512_hex($new_msg, $skey);

#	printf "got a thing: %s\n", $thing_hex;
	printf "got a thing: %s\n", fmt_hex_string($thing);

	return $thing;
}

sub get_sig2 {
	my ($msg, $skey, $seq) = @_;

	my $session_id = substr($msg, $SMB2_HDR_SESSION_ID, 8); # 64-bit session_id
	my $orig_sig = substr($msg, $SMB2_HDR_SIGNATURE, 16);
	my $new_msg = substr($msg, 0, $SMB2_HDR_SIGNATURE) . '\0'x16 . substr($msg, $SMB2_HDR_SIGNATURE + 16);

	my $ctx = Digest::SHA->new(512);

	printf "  adding session key: %s\n", fmt_hex_string($skey);
	$ctx->add($skey);

	printf "  adding bytes: %s\n", fmt_hex_string(substr($msg, 0, $SMB2_HDR_SIGNATURE));
	$ctx->add(substr($msg, 0, $SMB2_HDR_SIGNATURE));


	printf "  adding bytes: %s\n", fmt_hex_string(chr(0)x16);
	$ctx->add(chr(0)x16);

	printf "  adding bytes: %s\n", fmt_hex_string(substr($msg, $SMB2_HDR_SIGNATURE + 16));
	$ctx->add(substr($msg, $SMB2_HDR_SIGNATURE + 16));

	my $thing = $ctx->clone->hexdigest;
	printf "got a thing: %s\n", $thing;

	return $ctx->digest;
}

sub get_sig {
	return substr(get_sig1(@_), 0, 16);
}



sub get_sig_hex {
	my ($msg, $skey, $seq) = @_;

#	my $ctx = Digest::MD5->new;
	my $ctx = Digest::SHA->new(256);

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
	my ($msg, $skey, $seq) = @_;

printf "search_seq\n";

	if (scalar @_ == 0) {
		$hint = shift;
		if ($hint > $backtrack) { $hint -= $backtrack; }
		else { $hint = 0; }
	}

#	my $orig_sig = substr($msg, 14, 8);
	my $orig_sig = substr($msg, $SMB2_HDR_SIGNATURE, 16);
printf "signature from packet %s\n", fmt_hex_string($orig_sig);

	return get_sig($msg, $skey, $seq);


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



my $cmd;
$cmd = "tshark -2 -E header=n -T fields -e ntlmssp.auth.sesskey -r $pcap_filename ntlmssp.auth.sesskey";
#$ tshark $(tshark_fields ntlmssp.auth.sesskey) -2n -r trace.pcap ntlmssp.auth.sesskey
#5ea76c3d137f190eeee5c85ddffb23cd
open ($in, "$cmd |");
while (my $line = <$in>) {
        my %frame_info;
        $line =~ s/^\s|\s$//g;

	if ($line ne "") {
		$session_key = hex_bin $line;
		last;
	}
}
close($in);

printf "have a session key of %d bytes: %s\n", length $session_key, fmt_hex_string($session_key);




#my @tshark_fields = ( 'frame.number', '_ws.col.Info', 'smb.mid', 'smb.cmd',
#	'smb.signature', 'smb.session_key', 'smb.payload_len', 'smb.payload');

#my $cmd = "tshark -2 -O smb.raw_payload:TRUE -E header=y -E quote=d -E separator=\\; -T fields";
#foreach my $f (@tshark_fields) { $cmd .= " -e $f"; }
#$cmd .= " -r $pcap_filename 'smb'";




#$ tshark -2 -Eheader=y -E quote=d -E separator=\; -T fields -e frame.number -e tcp.len -e nbss.length -e smb2.header_len -e _ws.col.info -e smb2.msg_id -e smb2.cmd -e smb2.signature -e tcp.payload -r trace.pcap 'frame.number==18'
#frame.number;tcp.len;nbss.length;smb2.header_len;_ws.col.info;smb2.msg_id;smb2.cmd;smb2.signature;tcp.payload
#"18";"272";"268";"64";;"0";"0";"00000000000000000000000000000000";"0000010cfe534d424000000000000000000001000100000000000000000000000000000029360000000000000000000000000000000000000000000000000000000000004100030011030200766d390000000000000000000000000007000000000080000000800000008000621f12edc55cd801000000000000000080004a00d0000000604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173655f69676e6f7265000000000000010026000000000001002000010063d486dee8d55660dd9bbfdb330424e2b99fab80f1eb7bc1d2b70c34972ce9a30000020004000000000001000200"
#[sorenson@bearskin 3167906]$


my @tshark_fields = ( 'frame.number' , 'tcp.len', 'nbss.length', 'smb2.header_len', 'smb2.msg_id', 'smb2.cmd', 'smb2.signature','tcp.payload', '_ws.col.Info' );
#	'_ws.col.info', 'smb2.msg_id', 'smb2.cmd',
#	'smb2.signature', 'tcp.payload' );

$cmd = "tshark -2 -Eheader=y -E quote=d -E separator=\\; -T fields";
foreach my $f (@tshark_fields) { $cmd .= " -e $f"; }
$cmd .= " -r $pcap_filename smb2";

printf "command is %s\n", $cmd;

#open($in, "$cmd |");
open($in, "$cmd |");
my $fields_string = <$in>;
$fields_string =~ s/^\s|\s$//g;

my @fields = split(";", $fields_string);
my $field_count = scalar @fields;
my $last_seq = 0;



# first Session Setup response (with the NTLMSSP_CHALLENGE)
#  ntlmssp.ntlmserverchallenge
# second Session Setup request
# ntlmssp.ntlmv2_response.chal




my $signing_key_str = "4730de07b166eded4498e5b9b915f37e";
my $signing_key = hex_bin $signing_key_str;


#$session_key = hex_bin "c7f255d16bd120c57be0b0d7220967886b9c95449c8a52e6584ec2cd29fcd822";

#while (my $line = <$in>) {
while (my $line = <$in>) {
	my %frame_info;
	$line =~ s/^\s|\s$//g;

	printf "\n";
	my @frame_fields = split(";", $line);
	for (my $i = 0 ; $i < $field_count ; $i ++) {
		my $value = $frame_fields[$i];
		$value =~ s/^\"|\"$//g; # strip off the quotes
		my $field_name = $fields[$i];

		$frame_info{$field_name} = $value;
	}

	printf "Frame %d - ", $frame_info{'frame.number'};
	printf "%s\n", $frame_info{'_ws.col.Info'};

#	my @cmds = split(",", $frame_info{'smb2.cmd'});
#	my @msg_ids = split(",", $frame_info{'smb2.msg_id'});
#	my @sigs = split(",", $frame_info{'smb2.signature'});

#	my @payload_lengths = $frame_info{'smb2.header_len'};

#	my $trim_len = $frame_info{'tcp.len'} + 4; # nbss size
	my $trim_len = $frame_info{'tcp.len'} - $frame_info{'nbss.length'};

#	my @payload_lengths = split(",", $frame_info{'smb.payload_len'});
#	my @payloads = split(",", $frame_info{'smb.payload'});

	printf("tcp length: %d, nbss.length: %d, smb2.header_len: %d\n", $frame_info{'tcp.len'}, $frame_info{'nbss.length'}, $frame_info{'smb2.header_len'});
	printf("  trim length: %d\n", $trim_len);

	printf "\tmsg_id %d\n", $frame_info{'smb2.msg_id'};
	printf "\t\tsmb2.signature %s\n", $frame_info{'smb2.signature'};

	my $payload = substr($frame_info{'tcp.payload'}, ($trim_len * 2));

#	printf "\t\tpayload: %s\n", $payloads[$i];
#	my $cpay = hex_bin $payloads[$i];

printf "  payload len: %d\n", (length $payload)/2;
printf "  payload: %s\n", $payload;


		my $cpay = hex_bin $payload;

#printf "  now %d?\n", length $cpay;
#			, 0, 14));

		printf "length of smb payload: %d\n", length $cpay;

		if ($frame_info{'smb2.signature'} ne "00000000000000000000000000000000") {


#my $computed_sig = get_sig($cpay, $session_key, 0);
my $computed_sig = get_sig($cpay, $signing_key, 0);
#sub get_sig2 {
#        my ($msg, $skey, $seq) = @_;

printf "does my computed sig work?  %s\n", fmt_hex_string($computed_sig);


if (0) {
			my $seq = search_seq($cpay, $session_key, $last_seq);
printf "back from seqrch_se1\n";
			if (defined $seq) {
				printf "\t\tsequence: %d\n", $seq;
				$last_seq = $seq;
			} else {
				printf "\t\tsequence: UNKNOWN\n";
			}
}
		} else {
			printf "    no signature\n";
		}
#	}
#	if (!($frame_info{'smb.session_key'} =~ /^\s*$/)) {
#		# if we didn't have the session key, we should be able to set it from this
#		printf "\t\tsession key: %s\n", $frame_info{'smb.session_key'};
#	}
}
