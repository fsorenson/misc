#!/usr/bin/perl -w

#
#  tshark $(tshark_cols rpc.xid nfs.majorid4 nfs.scope rpc.auth.machinename nfs.machinename4 nfs.verifier4 nfs.nii_name4 nfs.session_id4 nfs.data nfs.clientid nfs.seqid) -r nfs.pcap -2n | ./parse.pl
#

use strict;
use warnings;

use Data::Dumper;

my @replacement_field_names = [ "nfs.opcode", "nfs.status" ];

my %replacements = ();


sub elab_nfs_client_id4 {
	my $val = shift;
	my $ret = "";

	$val =~ s/\s+$//;

	$ret = join("", map {chr hex} split(":", $val));

	#	for my $c (split(":", $val)) {

	#        kv= nfs.nfs_client_id4.id == 4c:69:6e:75:78:20:4e:46:53:76:34:2e:30:20:31:30:2e:30:2e:30:2e:32:32:2f:31:30:2e:31:30:2e:32:37:2e:33:38:20:74:63:70 
	return $ret;
}
sub elab_hexcolon_to_hexval {
	my $val = shift;

	$val =~ s/\s+$//;
	return join("", map {chr hex} split(":", $val));
}
sub elab_nfs_r_addr {
	my $val = shift;
	my $ret;
	my @matches;

	if (@matches = $val =~ /((?:[0-9]+.){3}(?:[0-9]+)).([0-9]+).([0-9]+)/) {
	#	my @matches = $val =~ /((?:(?:[0-9]+\.)){3}(?:[0-9]+))(?:.([0-9]+)){2}/;
	#	$val =~ /(?:([0-9]+.)){5}([0-9]+)/;
		$ret = sprintf("%s:%d", $matches[0], ($matches[1] * 256) + $matches[2]);
	} else {
		$ret = $val;
	}

if (0) {
#print Dumper \@matches;

	printf("val = %s\n", $val) if (defined($val));
	printf("1 = %s\n", $matches[1]) if (defined($matches[1]));
	printf("2 = %s\n", $matches[2]) if (defined($matches[2]));
	printf("3 = %s\n", $matches[3]) if (defined($matches[3]));
	printf("4 = %s\n", $4) if (defined($4));
	printf("5 = %s\n", $5) if (defined($5));

}

	return $ret;
}
sub elab_to_hex {
	my $v = shift;
	if ($v <= 0xffff) {
		return sprintf("0x%04x", $v);
	} elsif ($v <= 0xffffffff) {
		return sprintf("0x%08x", $v);
	} else {
		return sprintf("0x%016x", $v);
	}
}

# if we want to do bitmask
#$ tshark -G values | grep nfs.open4.share_access | awk 'BEGIN{ printf("my @vals = ();\n"); }  ($1=="V"){printf "push(@vals,\"%s\") if ($value == 0x%x);\n", $4, $3} END{ printf("return join(\"|\",@vals);\n") }'
sub elab_nfs_open {
	my $key = shift;
	my $value = shift;

	if ($key eq "nfs.open.opentype") {
		return "OPEN4_NOCREATE" if ($value eq "0");
		return "OPEN4_CREATE" if ($value eq "1");
	} elsif ($key eq "nfs.open.claim_type") {
		#$ tshark -G values | grep nfs.open.claim_type | awk '{printf "return \"%s\" if ($value eq \"%s\");\n", $4, $3}'
		return "CLAIM_NULL" if ($value eq "0");
		return "CLAIM_PREVIOUS" if ($value eq "1");
		return "CLAIM_DELEGATE_CUR" if ($value eq "2");
		return "CLAIM_DELEGATE_PREV" if ($value eq "3");
		return "CLAIM_FH" if ($value eq "4");
		return "CLAIM_DELEG_CUR_FH" if ($value eq "5");
		return "CLAIN_DELEG_CUR_PREV_FH" if ($value eq "6");
	} elsif ($key eq "nfs.open.delegation_type") {
		return "OPEN_DELEGATE_NONE" if ($value eq 0);
		return "OPEN_DELEGATE_READ" if ($value eq 1);
		return "OPEN_DELEGATE_WRITE" if ($value eq 2);
		return "OPEN_DELEGATE_NONE_EXT" if ($value eq 3);
	} elsif ($key eq "nfs.open4.share_access") {
		# $ tshark -G values | grep nfs.open4.share_access | awk '($1=="V"){printf "return \"%s\" if ($value == 0x%x);\n", $4, $3}'
		return "OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE" if ($value == 0x0);
		return "OPEN4_SHARE_ACCESS_READ" if ($value == 0x1);
		return "OPEN4_SHARE_ACCESS_WRITE" if ($value == 0x2);
		return "OPEN4_SHARE_ACCESS_BOTH" if ($value == 0x3);
		return "OPEN4_SHARE_ACCESS_WANT_READ_DELEG" if ($value == 0x100);
		return "OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG" if ($value == 0x200);
		return "OPEN4_SHARE_ACCESS_WANT_ANY_DELEG" if ($value == 0x300);
		return "OPEN4_SHARE_ACCESS_WANT_NO_DELEG" if ($value == 0x400);
		return "OPEN4_SHARE_ACCESS_WANT_CANCEL" if ($value == 0x500);
		return "OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL" if ($value == 0x10000);
		return "OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED" if ($value == 0x20000);
	} elsif ($key eq "nfs.open4.share_deny") {
		# $ tshark -G values | grep nfs.open4.share_deny | awk '($1=="V"){printf "return \"%s\" if ($value == 0x%x);\n", $4, $3}'
		return "OPEN4_SHARE_DENY_NONE" if ($value == 0x0);
		return "OPEN4_SHARE_DENY_READ" if ($value == 0x1);
		return "OPEN4_SHARE_DENY_WRITE" if ($value == 0x2);
		return "OPEN4_SHARE_DENY_BOTH" if ($value == 0x3);
	} elsif ($key eq "nfs.open.claim_type") {
		# $ tshark -G values | grep nfs.open.claim_type | awk '($1=="V"){printf "\t\treturn \"%s\" if ($value == 0x%x);\n", $4, $3}'
		return "CLAIM_NULL" if ($value == 0x0);
		return "CLAIM_PREVIOUS" if ($value == 0x1);
		return "CLAIM_DELEGATE_CUR" if ($value == 0x2);
		return "CLAIM_DELEGATE_PREV" if ($value == 0x3);
		return "CLAIM_FH" if ($value == 0x4);
		return "CLAIM_DELEG_CUR_FH" if ($value == 0x5);
		return "CLAIN_DELEG_CUR_PREV_FH" if ($value == 0x6);
	} elsif ($key eq "nfs.lock_owner4") {
		return elab_nfs_lock_owner4($value);
	} elsif ($key eq "nfs.open_owner4") {
		return elab_nfs_open_owner4($value);
	}
	return sprintf("key=*%s*  value=*%s*\n", $key, $value);
}
sub elab_nfs_layout {
	my $key = shift;
	my $value = shift;

	if ($key eq "nfs.layouttype") {
		# $ tshark -G values | grep nfs.layouttype | awk '($1=="V"){printf "\t\treturn \"%s\" if ($value == 0x%x);\n", $4, $3}'
		return "LAYOUT4_NFSV4_1_FILES" if ($value == 0x1);
		return "LAYOUT4_OSD2_OBJECTS" if ($value == 0x2);
		return "LAYOUT4_BLOCK_VOLUME" if ($value == 0x3);
		return "LAYOUT4_FLEX_FILES" if ($value == 0x4);
		return "LAYOUT4_SCSI" if ($value == 0x5);
	}
	return $value;
}

sub elab_nfs_iomode {
	my $value = shift;

	# $ tshark -G values | grep nfs.iomode | awk '($1=="V"){printf "\t\treturn \"%s\" if ($value == 0x%x);\n", $4, $3} END{ printf("\t\treturn $value\n")}'
	return "IOMODE_READ" if ($value == 0x1);
	return "IOMODE_RW" if ($value == 0x2);
	return "IOMODE_ANY" if ($value == 0x3);
	return $value;
}

#$ tshark -G values | grep nfs.createmode4 | awk '($1=="V"){printf "\t\treturn \"%s\" if ($value == 0x%x);\n", $4, $3}'
sub elab_nfs_createmode4 {
	my $value = shift;
	return "UNCHECKED4" if ($value == 0x0);
	return "GUARDED4" if ($value == 0x1);
	return "EXCLUSIVE4" if ($value == 0x2);
	return "EXCLUSIVE4_1" if ($value == 0x3);
	return $value;
}
sub elab_nfs_ftype4 {
	my $ft = shift;
	return "NF4REG" if ($ft == 1);
	return "NF4DIR" if ($ft == 2);
	return "NF4BLK" if ($ft == 3);
	return "NF4CHR" if ($ft == 4);
	return "NF4LNK" if ($ft == 5);
	return "NF4SOCK" if ($ft == 6);
	return "NF4FIFO" if ($ft == 7);
	return "NF4ATTRDIR" if ($ft == 8);
	return "NF4NAMEDATTR" if ($ft == 9);
	return $ft;
}

sub elab_nfs_locktype4 {
	my $lt = shift;
	return "READ_LT" if ($lt == 0x1);
	return "WRITE_LT" if ($lt == 0x2);
	return "READW_LT" if ($lt == 0x3);
	return "WRITEW_LT" if ($lt == 0x4);
	return "RELEASE_STATE" if ($lt == 0x5);
	return $lt;
}
sub elab_nfs_lock_owner4 {
	my $lo = shift;
	if (substr($lo, 0, 23) eq "6c:6f:63:6b:20:69:64:3a") {
		$lo = $lo . " (lock id: " . substr($lo, 24) . ")";
	}
	return $lo;
}
sub elab_nfs_open_owner4 {
	my $oo = shift;
	if (substr($oo, 0, 23) eq "6f:70:65:6e:20:69:64:3a") {
		$oo = $oo . " (open id: " . substr($oo, 24) . ")";
	}
}
sub elab_nfs_mode {
	my $m = shift;
	return sprintf("%#o", $m);
}
sub elab_nfs_set_it {
	my $m = shift;
	return "no value/don't change/SET_TO_SERVER_TIME4" if ($m == 0x0);
	return "value follows/set to server time/SET_TO_CLIENT_TIME4" if ($m == 0x1);
	return "set to client time" if ($m == 0x1);
	return $m;
}

sub elaborate_nfs {
	#	my ($key, $value) = $@;
	my $key = shift;
	my $value = shift;

	if ($key eq "nfs.nfs_client_id4.id") {
		$value = elab_nfs_client_id4($value)
	} elsif ($key eq "nfs.scope") {
		$value = elab_hexcolon_to_hexval($value)
	} elsif ($key eq "nfs.majorid4") {
		$value = elab_hexcolon_to_hexval($value)
	} elsif ($key eq "nfs.data") {
		$value = elab_hexcolon_to_hexval($value)
	} elsif ($key eq "nfs.r_addr") {
		$value = elab_nfs_r_addr($value);
	} elsif ($key eq "nfs.cookie4") {
		$value = elab_to_hex($value);
	} elsif ($key eq "nfs.changeid4") {
		$value = elab_to_hex($value);
	} elsif (substr($key, 0, 8) eq "nfs.open") {
		$value = elab_nfs_open($key, $value);
	} elsif (substr($key, 0, 10) eq "nfs.layout") {
		$value = elab_nfs_layout($key, $value);
	} elsif ($key eq "nfs.iomode") {
		$value = elab_nfs_iomode($value);
	} elsif ($key eq "nfs.createmode4") {
		$value = elab_nfs_createmode4($value);
	} elsif ($key eq "nfs.nfs_ftype4") {
		$value = elab_nfs_ftype4($value);
	} elsif ($key eq "nfs.locktype4") {
		$value = elab_nfs_locktype4($value);
	} elsif ($key eq "nfs.mode") {
		$value = elab_nfs_mode($value);
	} elsif ($key eq "nfs.set_it") {
		$value = elab_nfs_set_it($value);
	} elsif ($key eq "nfs.lock_owner4") {
		$value = elab_nfs_lock_owner4($value);
	} elsif ($key eq "nfs.open_owner4") {
		$value = elab_nfs_open_owner4($value)
	} else {
#		printf("key = '%s', value = '%s'\n", $key, $value);
	}

	return ($key, $value);
}

sub elaborate_smb2 {
	my $key = shift;
	my $value = shift;

	if ($key eq "smb2.create.disposition") {
		return "Supersede (supersede existing file (if it exists))" if ($value == 0);
		return "Open (if file exists open it, else fail)" if ($value == 1);
		return "Create (if file exists fail, else create it)" if ($value == 2);
		return "Open If (if file exists open it, else create it)" if ($value == 3);
		return "Overwrite (if file exists overwrite, else fail)" if ($value == 4);
		return "Overwrite If (if file exists overwrite, else create it)" if ($value == 5);
	}
	return $value;
}

# TODO
sub elaborate_kerberos {


}




sub elaborate {
	my $key = shift;
	my $value = shift;

	if (substr($key, 0, 4) eq "nfs.") {
		$value = elaborate_nfs($key, $value);
	} elsif (substr($key, 0, 5) eq "smb2.") {
		$value = elaborate_smb2($key, $value);
	} else {
		#
	}
	return ($key, $value);
}


while (<>) {
#	chomp;
	my $line = $_;
	$line =~ s/\n$//g;

#	printf("*$line*\n");
#	next;

#   20  10.431619 192.168.1.20 → 192.168.1.25 NFS 334 V4 Call (Reply In 21) EXCHANGE_ID  nfs.data == 4c:69:6e:75:78:20:4e:46:53:76:34:2e:31:20:6e:66:73:2d:63:6c:69:65:6e:74:2e:6e:6f:76:61:6c:6f:63:61:6c  nfs.verifier4 == 0x5af56ed61d164a00  rpc.auth.machinename == "nfs-client.novalocal" 
#   20  10.431619 192.168.1.20 → 192.168.1.25 NFS 334 V4 Call (Reply In 21) EXCHANGE_ID *
	#  * nfs.data == 4c:69:6e:75:78:20:4e:46:53:76:34:2e:31:20:6e:66:73:2d:63:6c:69:65:6e:74:2e:6e:6f:76:61:6c:6f:63:61:6c *
	#  * nfs.verifier4 == 0x5af56ed61d164a00 *
	#  * rpc.auth.machinename == "nfs-client.novalocal" *

#   21  10.431798 192.168.1.25 → 192.168.1.20 NFS 194 V4 Reply (Call In 20) EXCHANGE_ID  nfs.clientid == 0x856df55a8bff6e62 
#   22  10.431865 192.168.1.20 → 192.168.1.25 NFS 290 V4 Call (Reply In 23) CREATE_SESSION  nfs.clientid == 0x856df55a8bff6e62  nfs.machinename4 == "nfs-client.novalocal"  rpc.auth.machinename == "nfs-client.novalocal" 
#   23  10.432040 192.168.1.25 → 192.168.1.20 NFS 194 V4 Reply (Call In 22) CREATE_SESSION  nfs.session_id4 == 85:6d:f5:5a:8b:ff:6e:62:02:00:00:00:00:00:00:00 
#   24  10.432078 192.168.1.20 → 192.168.1.25 NFS 206 V4 Call (Reply In 30) SEQUENCE | RECLAIM_COMPLETE  nfs.session_id4 == 85:6d:f5:5a:8b:ff:6e:62:02:00:00:00:00:00:00:00  rpc.auth.machinename == "nfs-client.novalocal" 
#   25  10.432103 192.168.1.20 → 192.168.1.34 NFS 334 V4 Call (Reply In 26) EXCHANGE_ID  nfs.data == 4c:69:6e:75:78:20:4e:46:53:76:34:2e:31:20:6e:66:73:2d:63:6c:69:65:6e:74:2e:6e:6f:76:61:6c:6f:63:61:6c  nfs.verifier4 == 0x5af56ed61d164a00  rpc.auth.machinename == "nfs-client.novalocal" 
#   26  10.432262 192.168.1.34 → 192.168.1.20 NFS 194 V4 Reply (Call In 25) EXCHANGE_ID  nfs.clientid == 0x856df55a8bff6e62 
#   30  10.436667 192.168.1.25 → 192.168.1.20 NFS 158 V4 Reply (Call In 24) SEQUENCE | RECLAIM_COMPLETE  nfs.session_id4 == 85:6d:f5:5a:8b:ff:6e:62:02:00:00:00:00:00:00:00 

	my %matches;
	my @fields;

	$line =~ s/\[Packet size limited during capture\]//g;


#	if (my @captured = $line =~ /^(\s*[0-9]+\s+)(.+? )(?:( .+ == .+ )+?)$/) {

	my @test_fields;

	my $frame;
	my $desc;
	my $fields_str = "";

	if ($line =~ /^(?:\s*([0-9]+)\s+)(.+? )( [^\s]+ == .+)$/) {
		$frame = $1;
		$desc = $2;
		$fields_str = $3;
	} elsif ($line =~ /^(?:\s*([0-9]+)\s+)(.+)$/) {
		$frame = $1;
		$desc = $2;
	} else {
		printf("%s\n", $line);
		next;
	}

	while ($fields_str =~ /(.*)( .+ == .+(?:[ ]?))+$/) {
		push(@fields, $2);
		$fields_str = $1;
	}

	$desc = sprintf("%s %s", $desc, $fields_str);
	$desc =~ s/\s$//g;
	printf("%s  %s\n", $frame, $desc);
#	printf("%s%s%s\n", $frame, $desc, $fields_str);

	for my $f (@fields) {
		$f =~ /(?:[ ]?)(.+) == (.+)(?:[ ]?)/;
		my ($key, $val) = ($1, $2);
#			printf("\tkv=%22s == %s\n", $key, $val);

#			my ($key, $val) = elaborate($1, $2);
		$key =~ s/\s$//g;
		$val =~ s/\s$//g;
		($key, $val) = elaborate($key, $val);

		printf("\t%22s == %s\n", $key, $val);
	}

	next;


	if (my @captured = $line =~ /^(\s*[0-9]+\s+)(.+? )(?:( .+ == .+ )+?)$/) {
#		printf("line = *%s*\n", $line);

		my $frame = $1;
		my $desc = $2;

		my $fields_str = $3;
		while ($fields_str =~ /(.*)( .+ == .+ )+$/) {

if(0) {
			printf("  substring: %s\n", $fields_str);
			#			(( .+ == .+ )+)$

			printf("    match 1: %s\n", $1);
			printf("    match 2: %s\n", $2) if (defined($2));
			printf("    match 3: %s\n", $3) if (defined($3));
			printf("    match 4: %s\n", $4) if (defined($4));
}

			push(@fields, $2);
#	if (my @captured = $line =~ /\s*([0-9]+)(.+?)( ((?P<opts> .+? == .+? )*))*$/) {

		#\s*([0-9]+)(.+?)(?: )((?:( (.+?) == (.+?) )*)*)$
			$fields_str = $1;
		}
#		printf("    also: %s\n", $fields_str);

		printf("%s%s%s\n", $frame, $desc, $fields_str);

		for my $f (@fields) {
			$f =~ / (.+) == (.+) /;
			my ($key, $val) = ($1, $2);
#			printf("\tkv=%22s == %s\n", $key, $val);

#			my ($key, $val) = elaborate($1, $2);
			($key, $val) = elaborate($key, $val);

			printf("\t%22s == %s\n", $key, $val);
		}


		my $i = 1;

#printf("frame %d\n", $1);
#printf("captured ***\n");
#print Dumper \@captured;
#printf("***\n");

#printf("%d = '%s'\n", 1, $1);
#printf("%d = '%s'\n", 2, $2);
#printf("%d = '%s'\n", 3, $3);
#printf("%d = '%s'\n", 4, $4);


#		push @{ $matches{$_} }, $+{$_} for keys %+;


#		while (defined($[$i])) {
#			printf("\t%d = *%s*\n", $i, $[$i]);

#		}

#		print Dumper \%matches;

		printf("\n");
	} else {
		printf("%s\n", $line);
#		printf("couldn't match: '%s'\n", $line);
	}
}




