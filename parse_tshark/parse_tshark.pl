#!/usr/bin/perl -w

# Frank Sorenson <sorenson@redhat.com>
#
#  tshark $(tshark_cols rpc.xid nfs.majorid4 nfs.scope rpc.auth.machinename nfs.machinename4 nfs.verifier4 nfs.nii_name4 nfs.session_id4 nfs.data nfs.clientid nfs.seqid) -r nfs.pcap -2n | ./parse.pl
#

use strict;
use warnings;

use Data::Dumper;

$|++;

our $max_field_len = 0;
our $no_value_field_format;
our $field_format;

sub check_field_maxlen {
	my $this_field = shift;
	my $this_field_len = length($this_field);

	if ($this_field_len > $max_field_len) {
		$max_field_len = $this_field_len;
		$no_value_field_format = sprintf("    %%%ds\n", $max_field_len);
		$field_format = sprintf("    %%%ds == %%s\n", $max_field_len);
	}
}
check_field_maxlen(" "); # set it to an initial length


sub lookup_kv {
	my $fields_ref = shift;
	my %fields = %$fields_ref;
	my $key = shift;
	my $value = shift;
	my $tmp_val;

	if (defined($fields{$key})) {
		return $fields{$key}{$value} if (defined($fields{$key}{$value}));

		my $tmp_val = eval($value);
#		printf("value='$value' => '$tmp_val'\n");
		return $fields{$key}{$tmp_val} if (defined($fields{$key}{$tmp_val}));
	}
	return $value;
}

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

sub elab_nfs_open_owner4 {
	my $oo = shift;
	if (substr($oo, 0, 23) eq "6f:70:65:6e:20:69:64:3a") {
		$oo = $oo . " (open id: " . substr($oo, 24) . ")";
	}
}
# if we want to do bitmask
#$ tshark -G values | grep nfs.open4.share_access | awk 'BEGIN{ printf("my @vals = ();\n"); }  ($1=="V"){printf "push(@vals,\"%s\") if ($value == 0x%x);\n", $4, $3} END{ printf("return join(\"|\",@vals);\n") }'
sub elab_nfs_open {
	my $key = shift;
	my $value = shift;

	my %nfs_open_fields = (
		"nfs.open.opentype" => {
			0 => "OPEN4_NOCREATE",
			1 => "OPEN4_CREATE"},
		"nfs.open.claim_type" => {
			0 => "CLAIM_NULL",
			1 => "CLAIM_PREVIOUS",
			2 => "CLAIM_DELEGATE_CUR",
			3 => "CLAIM_DELEGATE_PREV",
			4 => "CLAIM_FH",
			5 => "CLAIM_DELEG_CUR_FH",
			6 => "CLAIN_DELEG_CUR_PREV_FH"},
		"nfs.open.delegation_type" => {
			0 => "OPEN_DELEGATE_NONE",
			1 => "OPEN_DELEGATE_READ",
			2 => "OPEN_DELEGATE_WRITE",
			3 => "OPEN_DELEGATE_NONE_EXT"},
		"nfs.open4.share_access" => {
			0x0 => "OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE",
			0x1 => "OPEN4_SHARE_ACCESS_READ",
			0x2 => "OPEN4_SHARE_ACCESS_WRITE",
			0x3 => "OPEN4_SHARE_ACCESS_BOTH",
			0x100 => "OPEN4_SHARE_ACCESS_WANT_READ_DELEG",
			0x200 => "OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG",
			0x300 => "OPEN4_SHARE_ACCESS_WANT_ANY_DELEG",
			0x400 => "OPEN4_SHARE_ACCESS_WANT_NO_DELEG",
			0x500 => "OPEN4_SHARE_ACCESS_WANT_CANCEL",
			0x10000 => "OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL",
			0x20000 => "OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED"},
		"nfs.open4.share_deny" => {
			0 => "OPEN4_SHARE_DENY_NONE",
			1 => "OPEN4_SHARE_DENY_READ",
			2 => "OPEN4_SHARE_DENY_WRITE",
			3 => "OPEN4_SHARE_DENY_BOTH"},
	);

	if ($key eq "nfs.open_owner4") {
		return elab_nfs_open_owner4($value);
	} else {
                $value = lookup_kv(\%nfs_open_fields, $key, $value);
        }

#	return sprintf("key=*%s*  value=*%s*\n", $key, $value);
	return $value;
}


sub elab_nfs_lock_owner4 {
	my $lo = shift;
	if (substr($lo, 0, 23) eq "6c:6f:63:6b:20:69:64:3a") {
		$lo = $lo . " (lock id: " . substr($lo, 24) . ")";
	}
	return $lo;
}
sub elab_nfs_mode {
	my $m = shift;
	return sprintf("%s => %#o", $m, $m);
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

	# populate with something like the following:
	# tshark -G values | grep nfs.nfsstat4 | awk '{if (last_field!=$2) {printf "\"%s\" => {\n", $2 ; last_field=$2} ; if ($1=="V"){printf "%s => \"%s\",\n", $3, $4}} END{if (last_field!=""){printf "},\n"}}' >nfsstat4_values
	# then:  :r nfsstat4_values
	# in the insertion spot
	my %nfs_fields = (
		"nfs.fattr3.type" => {
			1 => "Regular",
			2 => "Directory",
			3 => "Block",
			4 => "Character",
			5 => "Symbolic",
			6 => "Socket",
			7 => "Named",
		},
		"nfs.nfs_ftype4" => {
			1 => "NF4REG",
			2 => "NF4DIR",
			3 => "NF4BLK",
			4 => "NF4CHR",
			5 => "NF4LNK",
			6 => "NF4SOCK",
			7 => "NF4FIFO",
			8 => "NF4ATTRDIR",
			9 => "NF4NAMEDATTR"},
		"nfs.createmode4" => {
			0x0 => "UNCHECKED4",
			0x1 => "GUARDED4",
			0x2 => "EXCLUSIVE4",
			0x3 => "EXCLUSIVE4_1"},
		"nfs.layouttype" => {
			0x1 => "LAYOUT4_NFSV4_1_FILES",
			0x2 => "LAYOUT4_OSD2_OBJECTS",
			0x3 => "LAYOUT4_BLOCK_VOLUME",
			0x4 => "LAYOUT4_FLEX_FILES",
			0x5 => "LAYOUT4_SCSI"},
		"nfs.iomode" => {
			0x1 => "IOMODE_READ",
			0x2 => "IOMODE_RW",
			0x3 => "IOMODE_ANY"},
		"nfs.locktype4" => {
			0x1 => "READ_LT",
			0x2 => "WRITE_LT",
			0x3 => "READW_LT",
			0x4 => "WRITEW_LT",
			0x5 => "RELEASE_STATE"},
		"nfs.procedure_v3" => {
			0 => "NULL",
			1 => "GETATTR",
			2 => "SETATTR",
			3 => "LOOKUP",
			4 => "ACCESS",
			5 => "READLINK",
			6 => "READ",
			7 => "WRITE",
			8 => "CREATE",
			9 => "MKDIR",
			10 => "SYMLINK",
			11 => "MKNOD",
			12 => "REMOVE",
			13 => "RMDIR",
			14 => "RENAME",
			15 => "LINK",
			16 => "READDIR",
			17 => "READDIRPLUS",
			18 => "FSSTAT",
			19 => "FSINFO",
			20 => "PATHCONF",
			21 => "COMMIT"},
		"nfs.opcode" => {
			3 => "ACCESS",
			4 => "CLOSE",
			5 => "COMMIT",
			6 => "CREATE",
			7 => "DELEGPURGE",
			8 => "DELEGRETURN",
			9 => "GETATTR",
			10 => "GETFH",
			11 => "LINK",
			12 => "LOCK",
			13 => "LOCKT",
			14 => "LOCKU",
			15 => "LOOKUP",
			16 => "LOOKUPP",
			17 => "NVERIFY",
			18 => "OPEN",
			19 => "OPENATTR",
			20 => "OPEN_CONFIRM",
			21 => "OPEN_DOWNGRADE",
			22 => "PUTFH",
			23 => "PUTPUBFH",
			24 => "PUTROOTFH",
			25 => "READ",
			26 => "READDIR",
			27 => "READLINK",
			28 => "REMOVE",
			29 => "RENAME",
			30 => "RENEW",
			31 => "RESTOREFH",
			32 => "SAVEFH",
			33 => "SECINFO",
			34 => "SETATTR",
			35 => "SETCLIENTID",
			36 => "SETCLIENTID_CONFIRM",
			37 => "VERIFY",
			38 => "WRITE",
			39 => "RELEASE_LOCKOWNER",
			40 => "BACKCHANNEL_CTL",
			41 => "BIND_CONN_TO_SESSION",
			42 => "EXCHANGE_ID",
			43 => "CREATE_SESSION",
			44 => "DESTROY_SESSION",
			45 => "FREE_STATEID",
			46 => "GET_DIR_DELEGATION",
			47 => "GETDEVINFO",
			48 => "GETDEVLIST",
			49 => "LAYOUTCOMMIT",
			50 => "LAYOUTGET",
			51 => "LAYOUTRETURN",
			52 => "SECINFO_NO_NAME",
			53 => "SEQUENCE",
			54 => "SET_SSV",
			55 => "TEST_STATEID",
			56 => "WANT_DELEG",
			57 => "DESTROY_CLIENTID",
			58 => "RECLAIM_COMPLETE",
			59 => "ALLOCATE",
			60 => "COPY",
			61 => "COPY_NOTIFY",
			62 => "DEALLOCATE",
			63 => "IO_ADVISE",
			64 => "LAYOUTERROR",
			65 => "LAYOUTSTATS",
			66 => "OFFLOAD_CANCEL",
			67 => "OFFLOAD_STATUS",
			68 => "READ_PLUS",
			69 => "SEEK",
			70 => "WRITE_SAME",
			71 => "CLONE",
			72 => "GETXATTR",
			73 => "SETXATTR",
			74 => "LISTXATTRS",
			75 => "REMOVEXATTR",
			10044 => "ILLEGAL"},
		"nfs.nfsstat4" => {
			0 => "NFS4_OK",
			1 => "NFS4ERR_PERM",
			2 => "NFS4ERR_NOENT",
			5 => "NFS4ERR_IO",
			6 => "NFS4ERR_NXIO",
			13 => "NFS4ERR_ACCESS",
			17 => "NFS4ERR_EXIST",
			18 => "NFS4ERR_XDEV",
			19 => "NFS4ERR_DQUOT",
			20 => "NFS4ERR_NOTDIR",
			21 => "NFS4ERR_ISDIR",
			22 => "NFS4ERR_INVAL",
			27 => "NFS4ERR_FBIG",
			28 => "NFS4ERR_NOSPC",
			30 => "NFS4ERR_ROFS",
			31 => "NFS4ERR_MLINK",
			63 => "NFS4ERR_NAMETOOLONG",
			66 => "NFS4ERR_NOTEMPTY",
			69 => "NFS4ERR_DQUOT",
			70 => "NFS4ERR_STALE",
			10001 => "NFS4ERR_BADHANDLE",
			10003 => "NFS4ERR_BAD_COOKIE",
			10004 => "NFS4ERR_NOTSUPP",
			10005 => "NFS4ERR_TOOSMALL",
			10006 => "NFS4ERR_SERVERFAULT",
			10007 => "NFS4ERR_BADTYPE",
			10008 => "NFS4ERR_DELAY",
			10009 => "NFS4ERR_SAME",
			10010 => "NFS4ERR_DENIED",
			10011 => "NFS4ERR_EXPIRED",
			10012 => "NFS4ERR_LOCKED",
			10013 => "NFS4ERR_GRACE",
			10014 => "NFS4ERR_FHEXPIRED",
			10015 => "NFS4ERR_SHARE_DENIED",
			10016 => "NFS4ERR_WRONGSEC",
			10017 => "NFS4ERR_CLID_INUSE",
			10018 => "NFS4ERR_RESOURCE",
			10019 => "NFS4ERR_MOVED",
			10020 => "NFS4ERR_NOFILEHANDLE",
			10021 => "NFS4ERR_MINOR_VERS_MISMATCH",
			10022 => "NFS4ERR_STALE_CLIENTID",
			10023 => "NFS4ERR_STALE_STATEID",
			10024 => "NFS4ERR_OLD_STATEID",
			10025 => "NFS4ERR_BAD_STATEID",
			10026 => "NFS4ERR_BAD_SEQID",
			10027 => "NFS4ERR_NOT_SAME",
			10028 => "NFS4ERR_LOCK_RANGE",
			10029 => "NFS4ERR_SYMLINK",
			10030 => "NFS4ERR_READDIR_NOSPC",
			10031 => "NFS4ERR_LEASE_MOVED",
			10032 => "NFS4ERR_ATTRNOTSUPP",
			10033 => "NFS4ERR_NO_GRACE",
			10034 => "NFS4ERR_RECLAIM_BAD",
			10035 => "NFS4ERR_RECLAIM_CONFLICT",
			10036 => "NFS4ERR_BADXDR",
			10037 => "NFS4ERR_LOCKS_HELD",
			10038 => "NFS4ERR_OPENMODE",
			10039 => "NFS4ERR_BADOWNER",
			10040 => "NFS4ERR_BADCHAR",
			10041 => "NFS4ERR_BADNAME",
			10042 => "NFS4ERR_BAD_RANGE",
			10043 => "NFS4ERR_LOCK_NOTSUPP",
			10044 => "NFS4ERR_OP_ILLEGAL",
			10045 => "NFS4ERR_DEADLOCK",
			10046 => "NFS4ERR_FILE_OPEN",
			10047 => "NFS4ERR_ADMIN_REVOKED",
			10048 => "NFS4ERR_CB_PATH_DOWN",
			10049 => "NFS4ERR_BADIOMODE",
			10050 => "NFS4ERR_BADLAYOUT",
			10051 => "NFS4ERR_BAD_SESSION_DIGEST",
			10052 => "NFS4ERR_BADSESSION",
			10053 => "NFS4ERR_BADSLOT",
			10054 => "NFS4ERR_COMPLETE_ALREADY",
			10055 => "NFS4ERR_CONN_NOT_BOUND_TO_SESSION",
			10056 => "NFS4ERR_DELEG_ALREADY_WANTED",
			10057 => "NFS4ERR_DIRDELEG_UNAVAIL",
			10058 => "NFS4ERR_LAYOUTTRYLATER",
			10059 => "NFS4ERR_LAYOUTUNAVAILABLE",
			10060 => "NFS4ERR_NOMATCHING_LAYOUT",
			10061 => "NFS4ERR_RECALLCONFLICT",
			10062 => "NFS4ERR_UNKNOWN_LAYOUTTYPE",
			10063 => "NFS4ERR_SEQ_MISORDERED",
			10064 => "NFS4ERR_SEQUENCE_POS",
			10065 => "NFS4ERR_REQ_TOO_BIG",
			10066 => "NFS4ERR_REP_TOO_BIG",
			10067 => "NFS4ERR_REP_TOO_BIG_TO_CACHE",
			10068 => "NFS4ERR_RETRY_UNCACHED_REP",
			10069 => "NFS4ERR_UNSAFE_COMPOUND",
			10070 => "NFS4ERR_TOO_MANY_OPS",
			10071 => "NFS4ERR_OP_NOT_IN_SESSION",
			10072 => "NFS4ERR_HASH_ALG_UNSUPP",
			10073 => "NFS4ERR_CONN_BINDING_NOT_ENFORCED",
			10074 => "NFS4ERR_CLIENTID_BUSY",
			10075 => "NFS4ERR_PNFS_IO_HOLE",
			10076 => "NFS4ERR_SEQ_FALSE_RETRY",
			10077 => "NFS4ERR_BAD_HIGH_SLOT",
			10078 => "NFS4ERR_DEADSESSION",
			10079 => "NFS4ERR_ENCR_ALG_UNSUPP",
			10080 => "NFS4ERR_PNFS_NO_LAYOUT",
			10081 => "NFS4ERR_NOT_ONLY_OP",
			10082 => "NFS4ERR_WRONG_CRED",
			10083 => "NFS4ERR_WRONG_TYPE",
			10084 => "NFS4ERR_DIRDELEG_UNAVAIL",
			10085 => "NFS4ERR_REJECT_DELEG",
			10086 => "NFS4ERR_RETURNCONFLICT",
			10087 => "NFS4ERR_DELEG_REVOKED",
			10088 => "NFS4ERR_PARTNER_NOTSUPP",
			10089 => "NFS4ERR_PARTNER_NO_AUTH",
			10090 => "NFS4ERR_UNION_NOTSUPP",
			10091 => "NFS4ERR_OFFLOAD_DENIED",
			10092 => "NFS4ERR_WRONG_LFS",
			10093 => "NFS4ERR_BADLABEL",
			10094 => "NFS4ERR_OFFLOAD_NO_REQS",
			10095 => "NFS4ERR_NOXATTR",
			10096 => "NFS4ERR_XATTR2BIG",
		},
		"nfs.stable_how4" => {
			0 => "UNSTABLE4",
			1 => "DATA_SYNC4",
			2 => "FILE_SYNC4",
		},

		# nfs callbacks
		"nfs.cb_procedure" => {
			0 => "CB_NULL",
			1 => "CB_COMPOUND",
		},
		"nfs.cb.operation" => {
			3 => "CB_GETATTR",
			4 => "CB_RECALL",
			5 => "CB_LAYOUTRECALL",
			6 => "CB_NOTIFY",
			7 => "CB_PUSH_DELEG",
			8 => "CB_RECALL_ANY",
			9 => "CB_RECALLABLE_OBJ_AVAIL",
			10 => "CB_RECALL_SLOT",
			11 => "CB_SEQUENCE",
			12 => "CB_WANTS_CANCELLED",
			13 => "CB_NOTIFY_LOCK",
			14 => "CB_NOTIFY_DEVICEID",
			15 => "CB_OFFLOAD",
			10044 => "CB_ILLEGAL",
		},
	);

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
	} elsif ($key eq "nfs.mode" || $key eq "nfs.mode3") {
		$value = elab_nfs_mode($value);
	} elsif ($key eq "nfs.set_it") {
		$value = elab_nfs_set_it($value);
	} elsif ($key eq "nfs.lock_owner4") {
		$value = elab_nfs_lock_owner4($value);
	} else {
		$value = lookup_kv(\%nfs_fields, $key, $value);
	}

	return $value;
#	return ($key, $value);
}
sub elaborate_rpc {
	#	my ($key, $value) = $@;
	my $key = shift;
	my $value = shift;

	# populate with something like the following:
	# tshark -G values | grep nfs.nfsstat4 | awk '{if (last_field!=$2) {printf "\"%s\" => {\n", $2 ; last_field=$2} ; if ($1=="V"){printf "%s => \"%s\",\n", $3, $4}} END{if (last_field!=""){printf "},\n"}}' >nfsstat4_values
	# then:  :r nfsstat4_values
	# in the insertion spot
	my %rpc_fields = (
		"rpc.msgtyp" => {
			0 => "Call",
			1 => "Reply",
		},
		"rpc.auth.flavor" => {
			0 => "AUTH_NULL",
			1 => "AUTH_UNIX",
			2 => "AUTH_SHORT",
			3 => "AUTH_DES",
			5 => "AUTH_RSA/Gluster",
			6 => "RPCSEC_GSS",
			300001 => "AUTH_GSSAPI",
			390003 => "RPCSEC_GSS_KRB5",
			390004 => "RPCSEC_GSS_KRB5I",
			390005 => "RPCSEC_GSS_KRB5P",
			390006 => "RPCSEC_GSS_LIPKEY",
			390007 => "RPCSEC_GSS_LIPKEY_I",
			390008 => "RPCSEC_GSS_LIPKEY_P",
			390009 => "RPCSEC_GSS_SPKM3",
			390010 => "RPCSEC_GSS_SPKM3I",
			390011 => "RPCSEC_GSS_SPKM3P",
			390039 => "AUTH_GLUSTERFS",
		},
		"rpc.replystat" => {
			0 => "accepted",
			1 => "denied",
		},
		"rpc.state_reject" => {
			0 => "RPC_MISMATCH",
			1 => "AUTH_ERROR",
		},
		"rpc.state_auth" => {
			1 => "bad credential (seal broken)",
			2 => "client must begin new session",
			3 => "bad verifier (seal broken)",
			4 => "verifier expired or replayed",
			5 => "rejected for security reasons",
			13 => "GSS credential problem",
			14 => "GSS context problem",
		},
	);
	$value = lookup_kv(\%rpc_fields, $key, $value);

	return $value;
}

sub elaborate_smb {
	my $key = shift;
	my $value = shift;


	my %smb_fields = (
		"smb.dfs.referral.server.type" => {
			0 => "Non-root targets returned",
			1 => "Root targets returned"},
		"smb.dfs.flags.server_hold_storage" => {
			0 => "Server does not hold storage for the file",
			1 => "Server holds storage for the file"},
		"smb.dfs.flags.fielding" => {
			0 => "Server is not fielding capable",
			1 => "Server is fielding capable"},
		"smb2.dialect" => {
			0x202 => "SMB 2.0.2",
			0x210 => "SMB 2.1",
			0x2ff => "SMB2 wildcard",
			0x300 => "SMB 3.0",
			0x302 => "SMB 3.0.2",
			0x310 => "SMB 3.1.0",
			0x311 => "SMB 3.1.1",},
		"smb2.impersonation.level" => {
			0 => "Anonymous",
			1 => "Identification",
			2 => "Impersonation",
			3 => "Delegation"},
		"smb2.create.disposition" => {
			0 => "Supersede (supersede existing file (if it exists))",
			1 => "Open (if file exists open it, else fail)",
			2 => "Create (if file exists fail, else create it)",
			3 => "Open If (if file exists open it, else create it)",
			4 => "Overwrite (if file exists overwrite, else fail)",
			5 => "Overwrite If (if file exists overwrite, else create it)"},
		"smb.spi_loi" => {
			1 => "Info Standard",
			2 => "Info Set EAs",
			4 => "Info Query All EAs",
			257 => "Set File Basic Info",
			258 => "Set File Disposition Info",
			259 => "Set File Allocation Info",
			260 => "Set File End Of File Info",
			512 => "Set File Unix Basic",
			513 => "Set File Unix Link",
			514 => "Set File Unix HardLink",
			516 => "Set File Unix ACL",
			517 => "Set File Unix XATTR",
			518 => "Set File Unix Attr Flags",
			520 => "Set File Posix Lock",
			521 => "Set File Posix Open",
			522 => "Set File Posix Unlink",
			523 => "Set File Unix Info2",
			1004 => "Set File Basic Info",
			1010 => "Set Rename Information",
			1013 => "Set Disposition Information",
			1014 => "Set Position Information",
			1016 => "Set Mode Information",
			1019 => "Set Allocation Information",
			1020 => "Set EOF Information",
			1023 => "Set File Pipe Information",
			1025 => "Set File Pipe Remote Information",
			1029 => "Set Copy On Write Information",
			1032 => "Set OLE Class ID Information",
			1039 => "Set Inherit Context Index Information",
			1040 => "Set OLE Information (?)"},
		"smb.qpi_loi" => {
			1 => "Info Standard",
			2 => "Info Query EA Size",
			3 => "Info Query EAs From List",
			4 => "Info Query All EAs",
			6 => "Info Is Name Valid",
			257 => "Query File Basic Info",
			258 => "Query File Standard Info",
			259 => "Query File EA Info",
			260 => "Query File Name Info",
			263 => "Query File All Info",
			264 => "Query File Alt Name Info",
			265 => "Query File Stream Info",
			267 => "Query File Compression Info",
			512 => "Query File Unix Basic",
			513 => "Query File Unix Link",
			514 => "Query File Unix Hardlink",
			516 => "Query File Posix ACL",
			517 => "Query File Posix XATTR",
			518 => "Query File Posix Attr Flags",
			519 => "Query File Posix Permissions",
			520 => "Query File Posix Lock",
			523 => "Query File Unix Info2",
			1004 => "Query File Basic Info",
			1005 => "Query File Standard Info",
			1006 => "Query File Internal Info",
			1007 => "Query File EA Info",
			1009 => "Query File Name Info",
			1010 => "Query File Rename Info",
			1011 => "Query File Link Info",
			1012 => "Query File Names Info",
			1013 => "Query File Disposition Info",
			1014 => "Query File Position Info",
			1015 => "Query File Full EA Info",
			1016 => "Query File Mode Info",
			1017 => "Query File Alignment Info",
			1018 => "Query File All Info",
			1019 => "Query File Allocation Info",
			1020 => "Query File End of File Info",
			1021 => "Query File Alt Name Info",
			1022 => "Query File Stream Info",
			1023 => "Query File Pipe Info",
			1024 => "Query File Pipe Local Info",
			1025 => "Query File Pipe Remote Info",
			1026 => "Query File Mailslot Query Info",
			1027 => "Query File Mailslot Set Info",
			1028 => "Query File Compression Info",
			1029 => "Query File ObjectID Info",
			1030 => "Query File Completion Info",
			1031 => "Query File Move Cluster Info",
			1032 => "Query File Quota Info",
			1033 => "Query File Reparsepoint Info",
			1034 => "Query File Network Open Info",
			1035 => "Query File Attribute Tag Info",
			1036 => "Query File Tracking Info",
			1037 => "Query File Maximum Info"},
		"smb.qfsi_loi" => {
			18 => "qfsi_vals	[Binary Search]",
			1 => "Info Allocation",
			2 => "Info Volume",
			257 => "Query FS Label Info",
			258 => "Query FS Volume Info",
			259 => "Query FS Size Info",
			260 => "Query FS Device Info",
			261 => "Query FS Attribute Info",
			512 => "Unix Query FS Info",
			514 => "Unix Query POSIX whoami",
			769 => "Mac Query FS Info",
			1001 => "Query FS Label Info",
			1002 => "Query FS Volume Info",
			1003 => "Query FS Size Info",
			1004 => "Query FS Device Info",
			1005 => "Query FS Attribute Info",
			1006 => "Query FS Quota Info",
			1007 => "Query Full FS Size Info",
			1008 => "Object ID Information"},
	);
	$value = lookup_kv(\%smb_fields, $key, $value);

	return $value;
}
sub elaborate_nbss {
	my $key = shift;
	my $value = shift;

	my $orig = $value;
	my %nbss_fields = (
		"nbss.type" => {
			0x00 => "Session message",
			0x81 =>	"Session request",
			0x82 => "Positive session response",
			0x83 => "Negative session response",
			0x84 => "Retarget session response",
			0x85 => "Session keep-alive",
		},
	);

	$value = lookup_kv(\%nbss_fields, $key, $value);

	return $value;
}
sub elaborate_nlm {
	my $key = shift;
	my $value = shift;
#	my $orig = $value;

	# $ tshark -G values | grep nlm.stat | awk '{if (last_field!=$2) {printf "\"%s\" => {\n", $2 ; last_field=$2} ; if ($1=="V"){printf "%s => \"%s\",\n", $3, $4}} END{if (last_field!=""){printf "},\n"}}'
	my %nlm_fields = (
		"nlm.stat" => {
			0 => "NLM_GRANTED",
			1 => "NLM_DENIED",
			2 => "NLM_DENIED_NOLOCKS",
			3 => "NLM_BLOCKED",
			4 => "NLM_DENIED_GRACE_PERIOD",
			5 => "NLM_DEADLCK",
			6 => "NLM_ROFS",
			7 => "NLM_STALE_FH",
			8 => "NLM_BIG",
			9 => "NLM_FAILED",
		},
	);

	$value = lookup_kv(\%nlm_fields, $key, $value);
	return $value;
}

# TODO
sub elaborate_kerberos {


}
sub elaborate_stat {
	my $key = shift;
	my $value = shift;

	my %stat_fields = (
		"stat.procedure_v1" => {
			0 => "NULL",
			1 => "STAT",
			2 => "MON",
			3 => "UNMON",
			4 => "UNMON_ALL",
			5 => "SIMU_CRASH",
			6 => "NOTIFY" },
	);

	if (defined($stat_fields{$key})) {
		if (defined($stat_fields{$key}{$value})) {
			$value = $stat_fields{$key}{$value};
		}
	}
	return $value;
}

sub elaborate_other {
	my $key = shift;
	my $value = shift;

	my %fields = (
		"spnego.MechType" => {
			"1.3.6.1.4.1.311.2.2.10" => "NTLMSSP",
			"1.2.840.113554.1.2.2" => "KRB5",
			"1.2.840.48018.1.2.2" => "MS KRB5",
		},
		"spnego.supportedMech" => {
			"1.3.6.1.4.1.311.2.2.10" => "NTLMSSP",
			"1.2.840.113554.1.2.2" => "KRB5",
			"1.2.840.48018.1.2.2" => "MS KRB5",
		},
	);
	if (defined($fields{$key})) {
		if (defined($fields{$key}{$value})) {
			$value = $fields{$key}{$value};
		}
	}
	return $value;
}

sub elaborate {
	my $key = shift;
	my $value = shift;

	if (substr($key, 0, 4) eq "nfs.") {
		$value = elaborate_nfs($key, $value);
	} elsif (substr($key, 0, 4) eq "rpc.") {
		$value = elaborate_rpc($key, $value);
	} elsif (substr($key, 0, 4) eq "smb." || substr($key, 0, 5) eq "smb2.") {
		$value = elaborate_smb($key, $value);
	} elsif (substr($key, 0, 5) eq "stat.") {
		$value = elaborate_stat($key, $value);
	} elsif (substr($key, 0, 5) eq "nbss.") {
		$value = elaborate_nbss($key, $value);
	} elsif (substr($key, 0, 4) eq "nlm.") {
		$value = elaborate_nlm($key, $value);
	} else {
		$value = elaborate_other($key, $value);
	}
	return ($key, $value);
}


# some fields do not contain values; they simply exist or do not.  We'll need to handle these by knowing the patterns, and looking for them
#
# all categories:  tshark -G fields | grep -w FT_NONE | awk -F\\t '{print $3}' | awk -F. '{print $1}' | sort -u | wc -l
# 969
#
# # get lists in this way:
# $ for f in nfs rpc ip tcp ; do echo "tshark -G fields | grep -w FT_NONE | egrep '\s($f)\.' | awk -F\\\t '{print \$3}' | awk '{printf \"%s \", \$1} END{printf \"\n\"}'" ; done
# tshark -G fields | grep -w FT_NONE | egrep '\s(nfs)\.' | awk -F\\t '{print $3}' | awk '{printf "%s ", $1} END{printf "\n"}'
# tshark -G fields | grep -w FT_NONE | egrep '\s(rpc)\.' | awk -F\\t '{print $3}' | awk '{printf "%s ", $1} END{printf "\n"}'
# tshark -G fields | grep -w FT_NONE | egrep '\s(ip)\.' | awk -F\\t '{print $3}' | awk '{printf "%s ", $1} END{printf "\n"}'
# tshark -G fields | grep -w FT_NONE | egrep '\s(tcp)\.' | awk -F\\t '{print $3}' | awk '{printf "%s ", $1} END{printf "\n"}'
#
# $ tshark -G fields | grep -w FT_NONE | egrep '\s(nfs|rpc|ip|tcp|smb|smb2)\.' | awk -F\\t '{print $3}' | grep smb | awk '{printf "%s ", $1} END{printf "\n"}'
# smb.segment.segments smb.missing_word_parameters smb.information_level.malformed ...

#my @no_value_fields_list = qw ( tcp.analysis.spurious_retransmission tcp.analysis.retransmission );
my @no_value_fields_list;

# $ tshark -G fields | grep -w FT_NONE | egrep '\s(ip)\.' | awk -F\\t '{print $3}' | awk '{printf "%s ", $1} END{printf "\n"}'
push(@no_value_fields_list, qw ( ip.opt.len.invalid ip.opt.ptr.before_address ip.opt.ptr.middle_address ip.subopt_too_long ip.nop ip.bogus_ip_length ip.evil_packet ip.checksum_bad.expert ip.ttl.lncb ip.ttl.too_small ip.cipso.malformed ip.bogus_ip_version ip.bogus_header_length rtpproxy.notify_no_ip ));

# $ tshark -G fields | grep -w FT_NONE | egrep '\s(tcp)\.' | awk -F\\t '{print $3}' | awk '{printf "%s ", $1} END{printf "\n"}'
push(@no_value_fields_list, qw ( tcp.analysis tcp.analysis.flags tcp.analysis.duplicate_ack tcp.segments tcp.options.tfo.request tcp.option.len.invalid tcp.analysis.retransmission tcp.analysis.fast_retransmission tcp.analysis.spurious_retransmission tcp.analysis.out_of_order tcp.analysis.reused_ports tcp.analysis.lost_segment tcp.analysis.ack_lost_segment tcp.analysis.window_update tcp.analysis.window_full tcp.analysis.keep_alive tcp.analysis.keep_alive_ack tcp.analysis.zero_window_probe tcp.analysis.zero_window tcp.analysis.zero_window_probe_ack tcp.analysis.tfo_syn tcp.options.snack.sequence tcp.options.wscale.shift.invalid tcp.short_segment tcp.ack.nonzero tcp.connection.sack tcp.connection.syn tcp.connection.fin tcp.connection.rst tcp.checksum.ffff tcp.checksum_bad.expert tcp.urgent_pointer.non_zero tcp.suboption_malformed tcp.nop tcp.bogus_header_length ));

# smb/smb2
# $ tshark -G fields | grep -w FT_NONE | egrep '\s(smb|smb2)\.' | awk -F\\t '{print $3}' | awk '{printf "%s ", $1} END{printf "\n"}'
push(@no_value_fields_list, qw ( smb.segment.segments smb.missing_word_parameters smb.information_level.malformed smb.not_implemented smb.nt_transaction_setup.unknown smb.posix_acl.ace_type.unknown smb.info_level_unknown smb.info_level_not_understood smb2.ioctl.out smb2.ioctl.in smb2.file_all_info smb2.file_allocation_info smb2.file_endoffile_info smb2.file_alternate_name_info smb2.file_stream_info smb2.file_pipe_info smb2.file_compression_info smb2.file_basic_info smb2.file_standard_info smb2.file_internal_info smb2.file_mode_info smb2.file_alignment_info smb2.file_position_info smb2.file_access_info smb2.file_ea_info smb2.file_network_open_info smb2.file_attribute_tag_info smb2.file_disposition_info smb2.file_full_ea_info smb2.file_rename_info smb2.fs_volume_info smb2.fs_size_info smb2.fs_device_info smb2.fs_attribute_info smb2.fs_control_info smb2.fs_full_size_info smb2.fs_objectid_info smb2.sec_info_00 smb2.quota_info smb2.query_quota_info smb2.create.extrainfo smb2.create.chain_data smb2.FILE_OBJECTID_BUFFER smb2.channel_info_blob smb2.notify.out smb2.notify.info smb2.find.file_directory_info smb2.find.full_directory_info smb2.find.both_directory_info smb2.find.id_both_directory_info smb2.lock_info smb2.server_component_smb2 smb2.server_component_smb2_transform smb2.truncated smb2.pipe.fragments smb2.symlink_error_response smb2.SYMBOLIC_LINK_REPARSE_DATA_BUFFER smb2.invalid_length smb2.bad_response smb2.invalid_getinfo_offset smb2.invalid_getinfo_size smb2.empty_getinfo_buffer ));

# tshark -G fields | grep -w FT_NONE | egrep '\s(nfs)\.' | awk -F\t '{print $3}' | awk '{printf "%s ", } END{printf "\n"}'
push(@no_value_fields_list, qw ( nfs.readdir.entry nfs.flavors.info nfs.test_stateid.stateids nfs.test_stateid.results nfs.too_many_ops nfs.not_vnx_file nfs.protocol_violation nfs.too_many_bitmaps nfs.stateid.deprecated ));

# $ tshark -G fields | grep -w FT_NONE | egrep '\s(rpc)\.' | awk -F\\t '{print $3}' | awk '{printf "%s ", $1} END{printf "\n"}'
push(@no_value_fields_list, qw ( rpc.dup rpc.array_no_values rpc.fragments rpc.unknown_body rpc.cannot_dissect ));

my $no_value_fields_str = "(.+ )(" . join("|", @no_value_fields_list) . ")+( .*|\$)";
my $no_value_fields_re = qr/$no_value_fields_str/;

while (<>) {
	my $line = $_;
	$line =~ s/\n$//g;
	$line =~ s/\[Packet size limited during capture\]//g;

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
	my @no_value_fields;

	my $frame;
	my $desc;
	my $fields_str = "";

	while ($line =~ $no_value_fields_re) {
#		printf("found %s\n", $2);
		check_field_maxlen($2);
		push(@no_value_fields, $2);
		$line = $1;
		$line = $line . " " . $3 if (defined($3));
	}

	if ($line =~ /^(?:\s*([0-9]+)\s+)(.+?[\s]{0,})( [^\s]+ == .+)$/) {
		$frame = $1;
		$desc = $2;
		$fields_str = $3;
	} elsif ($line =~ /^(?:\s*([0-9]+)\s+)(.+)$/) {
		$frame = $1;
		$desc = $2;
# no fields str?
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


	# adjust field lengths, if necessary
	for my $f (@no_value_fields) {
		check_field_maxlen($f);
	}
	for my $f (@fields) {
		$f =~ /(?:[ ]?)(.+) == (.+)(?:[ ]?)/;
		check_field_maxlen($1);
	}

	for my $f (@no_value_fields) {
		printf($no_value_field_format, $f);
	}
	for my $f (@fields) {
		$f =~ /(?:[ ]?)(.+) == (.+)(?:[ ]?)/;
		my ($key, $val) = ($1, $2);
#			printf("\tkv=%22s == %s\n", $key, $val);

#			my ($key, $val) = elaborate($1, $2);
		$key =~ s/\s$//g;
		$val =~ s/\s$//g;
		($key, $val) = elaborate($key, $val);

		printf($field_format, $key, $val);
	}

	next;

##### nothing but old garbage below here
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

		printf("%s%s%s\n", $frame, $desc, $fields_str);

		for my $f (@fields) {
			$f =~ / (.+) == (.+) /;
			my ($key, $val) = ($1, $2);

#			my ($key, $val) = elaborate($1, $2);
			($key, $val) = elaborate($key, $val);

			printf("  %28s == %s\n", $key, $val);
		}


		my $i = 1;

		printf("\n");
	} else {
		printf("%s\n", $line);
#		printf("couldn't match: '%s'\n", $line);
	}
}
