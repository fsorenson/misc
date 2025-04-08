#!/usr/bin/perl -w





use strict;
use warnings;
use POSIX;
use Sys::Syslog;

my $log_ident = 'cifs-upcall-helper';
my $helper_version = '0.1';
my $debug_level = 1;
# 0 - only errors (LOG_ERR)
# 1 - relevant messages (LOG_INFO)
# 2 - verbose debugging (LOG_INFO)

my $upcall_conf = '/etc/cifs-upcall.conf';
my %upcall_opts = ();
my @upcall_args = ( '/usr/sbin/cifs.upcall' );
my $keyid;

my $split_char = '[,;]'; # separator for match and options fields

#*|match_field=value_glob[;match_field=value_glob]	*|config_field=config_value[;config_field=config_value]
#
#<selection_criteria> <options>
# selection criteria:
#     *
#     host<string_comparator><host_string>
#     user<string_comparator><user_string>
#     sec<string_comparator><sec_string>
#       ('krb5' or 'mskrb5')

#     ip=<ip_string>
#     ip4<ip4_comparator>ip4_string>
#     ip6=<ip6_string>  TODO

#     uid<numeric_comparator><uid_string>
#     creduid<numeric_comparator><uid_string>

# selection comparators:
#     string_comparators for host, user, and sec are the following: '=', '==', '!=', '~', or '!~'
#       '=', '==', and '!=' compare as 'globs'
#       '~' and '!~' compare as 'regexes'

#     ip4_comparators are: '=', '==', '!='
#     ip4_string accepts the following formats
#       bare ip:
#         www.xxx.yyy.zzz
#       ip_low-ip_high range:
#         aaa.bbb.ccc.ddd-www.xxx.yyy.zzz
#       ip_network/netmask:
#         www.xxx.yyy.zzz/aaa.bbb.ccc.ddd
#     ip_network/prefix (cidr):
#         www.xxx.yyy.zzz/nn

#     invalid netmask/prefix results in 'not a match', regardless of comparator

#     numeric_comparators for uid and creduid are the following: '<', '<=', '=', '==', '>=', '>', or '!='
#     uid_string may be decimal or hex (when beginning with 0x)
#
# options:
#     keytab=</path>
#     krb5conf=</path>
#     expire=<timeout>
#     use-proxy|use_proxy
#     no-env-probe|no_env_probe
#     trust-dns|trust_dns
#     legacy-uid|legacy_uid
#
# additional 'special case' selection value:
#     default|defaults - does not match, but clears default values and sets them to the specified options
#     (use option '*' or '-' to clear without setting any further options)
#
#     NOTE: default must be the only criteria
#

my $key_description_re = qr/cifs.spnego;([0-9]+);([0-9]+);([0-9a-f]+);ver=0x2;host=([^;]+);(ip4|ip6)=([^;]+);sec=(krb5|mskrb5);uid=(0x[0-9a-f]+);creduid=(0x[0-9a-f]+);user=([^;]+);pid=(0x[0-9a-f]+)/;
# describe format:
#  897516324: als--v-----v------------     0     0 cifs.spnego: ver=0x2;host=vm1;ip4=192.168.122.73;sec=krb5;uid=0x0;creduid=0x0;user=user1;pid=0xb302c
# rdescribe format:
#  cifs.spnego;0;0;39010000;ver=0x2;host=vm1;ip4=192.168.122.73;sec=krb5;uid=0x0;creduid=0x0;user=user1;pid=0xbaf7d

my $conf_split_re = qr/^([^\s]+)\s+(.+)/;
my $string_comparison_re = qr/(host|user|sec)(=|==|!=|~|!~)(.+)/;
my $uid_comparison_re = qr/^(uid|creduid)(<|<=|=|==|>=|>|!=)(0x[0-9a-f]+|[0-9]+)$/;

my $octet_re = qr/\d{1,2}|[01]\d{2}|2[0-4]\d|25[0-5]/;
my $ip4_re = qr/(?:$octet_re\.){3}$octet_re/;
my $ip4_range_re = qr/($ip4_re)-($ip4_re)/;
my $ip4_nm_re = qr/($ip4_re)\/($ip4_re)/;
my $ip4_cidr_re = qr/($ip4_re)\/(\d+)/;
my $ip4_comparison_re = qr/^ip4(=|==|!=)(\*|$ip4_re|$ip4_range_re|$ip4_nm_re|$ip4_cidr_re)$/;

sub log_msg {
	my $log_level = shift;
#	my @upcall_args = @_;
	my $msg = shift;
	my $syslog_level = 'info';

	$syslog_level = 'err' if $log_level < 1; # promote
printf "logging message: %s\n", $msg;
	syslog($syslog_level, $msg) if ($debug_level >= $log_level);
}
sub get_key_description {
	my $keyid = shift;

	my $cmd = "keyctl rdescribe $keyid";
	open KEYCTL, $cmd . " 2>&1 |" or die "Error executing keyctl: $!";
	my $rdescribe = <KEYCTL>;
	chomp $rdescribe;
	close KEYCTL;
	if ($?) {
		log_msg 0, "Error executing keyctl: $rdescribe";
#		printf "Error executing keyctl: $rdescribe\n";
		exit -1;
	};
	
	log_msg 2, "description for key $keyid: $rdescribe";
	return $rdescribe;
}
sub set_upcall_opts {
	my $opts_str = shift;

#	return if $opts_str eq '*';

	my @opts = split /$split_char/, $opts_str;
	foreach my $opt (@opts) {
		if ((my $field, my $val) = $opt =~ /^([^=]+)=(.+)$/) {
			if ($field eq 'keytab') {
				$upcall_opts{'keytab'} = $val;
			} elsif ($field eq 'krb5conf') {
				$upcall_opts{'krb5conf'} = $val;
			} elsif ($field eq 'expire') {
				$upcall_opts{'expire'} = $val;
			} else {
				log_msg 0, "unrecognized upcall option: $opt";
			}
		} elsif ($opt eq 'use_proxy' or $opt eq 'use-proxy') {
			$upcall_opts{'use_proxy'} = 1;
		} elsif ($opt eq 'legacy_uid' or $opt eq 'legacy-uid') {
			$upcall_opts{'legacy_uid'} = 1;
		} elsif ($opt eq 'trust_dns' or $opt eq 'trust-dns') {
			$upcall_opts{'trust_dns'} = 1;
		} elsif ($opt eq 'no_env_probe' or $opt eq 'no-env-probe') {
			$upcall_opts{'no_env_probe'} = 1;
		} elsif ($opt eq '*' or $opt eq '-') {
		} else {
			log_msg 0, "unrecognized upcall option: $opt";
		}
	}
}
sub set_upcall_args {
	foreach my $opt (keys %upcall_opts) {
		if ($opt eq 'keytab') {
			push @upcall_args, ('-K', $upcall_opts{$opt});
		} elsif ($opt eq 'krb5conf') {
			push @upcall_args, ('-k', $upcall_opts{$opt});
		} elsif ($opt eq 'expire') {
			push @upcall_args, ('-e', $upcall_opts{$opt});
		} elsif ($opt eq 'use_proxy') {
			$ENV{'GSS_USE_PROXY'} = 'yes';
		} elsif ($opt eq 'legacy_uid') {
			push @upcall_args, '-l';
		} elsif ($opt eq 'trust_dns') {
			push @upcall_args, '-t';
		} elsif ($opt eq 'no_env_probe') {
			push @upcall_args, '-E';
		}
	}
}
sub exec_upcall {
	set_upcall_args;
	push @upcall_args, $keyid;

	log_msg 1, sprintf("executing cifs.upcall: %s", join(' ', @upcall_args));
	exec { $upcall_args[0] } @upcall_args;
}

# matching logic
sub check_string_match {
	my $key_field_val = shift;
	my $comparator = shift;
	my $match_str = shift;

	if ($comparator eq '=' or $comparator eq '==' or $comparator eq '!=') { # glob
		$match_str =~ s/\./\\./g; # replace . with \.
		$match_str =~ s/\*/\.\*/g; # replace * with .*
	}

	my $result = 1 if ($key_field_val =~ $match_str);;
	$result = $result ^ 1 if (substr($comparator, 0, 1) eq '!');

	return $result;
}
sub check_uid_match {
	my $key_uid = shift;
	my $comparison = shift;
	my $comparison_uid = shift;

	$comparison_uid = scalar POSIX::strtol($comparison_uid, 16) if (substr($comparison_uid, 0, 2) eq '0x');

	my $comparison_string = sprintf("%d %s %d", $key_uid, $comparison, $comparison_uid);
	return 1 if (eval $comparison_string);
	return 0;
}
sub ip4_to_decimal {
	my $ip4 = shift;

	my @bytes = split /\./, $ip4;
	return $bytes[0] * 2**24 + $bytes[1] * 2**16 + $bytes[2] * 2**8 + $bytes[3];
}
sub check_ip4_match {
	my $key_ip4 = shift;
	my $comparator = shift;
	my $match_str = shift;

	log_msg 2, "check_ip4_match(key_ip: %s, comparator: %s, match_str: %s)", $key_ip4, $comparator, $match_str;

	my $negate = ($comparator eq '!=') ? 1 : 0;
	log_msg 2, "negating match in check_ip4_match" if $negate;

	my ($ip4_net_addr, $ret);

	if ($match_str eq '*') {
		log_msg 2, "ip4 match is '*' (always true)%s",
			($negate ? " but negated" : "");
		return $negate ? 0 : 1;
	} elsif ((my $ip4_addr) = $match_str =~ "^($ip4_re)\$") {
		log_msg 2, "ip4 match is a simple ip";

		$ret = ($key_ip4 eq $ip4_addr) ? 1 : 0;
		return $ret ^ $negate;
        } elsif ((my $ip4_range_low, my $ip4_range_high) = $match_str =~ "^($ip4_range_re)\$") {
		log_msg 2, "ip4 match is an ip range";

		$ip4_range_low = ip4_to_decimal $ip4_range_low;
		$ip4_range_high = ip4_to_decimal $ip4_range_high;
		$key_ip4 = ip4_to_decimal $key_ip4;

		$ret = ($key_ip4 >= $ip4_range_low and $key_ip4 <= $ip4_range_high) ? 1 : 0;
		return $ret ^ $negate;
        } elsif (($ip4_net_addr, my $ip4_netmask) = $match_str =~ "^($ip4_nm_re)\$") {
		log_msg 2, "ip4 match is an ip/netmask";


		# validate that netmask is valid: bits of 1s, followed by bits of zeros
		$ip4_netmask = ip4_to_decimal $ip4_netmask;
		my $ip4_netmask_str = sprintf("%032b", $ip4_netmask);

		# call an invalid netmask 'not a match', regardless of comparator
		log_msg 0, "invalid netmask in ip4 match: '$ip4_netmask_str'" if ($ip4_netmask_str !~ /^1*0*$/);
		return 0 if ($ip4_netmask_str !~ /^1*0*$/);

		$key_ip4 = ip4_to_decimal $key_ip4;
		my $ip4_range_low = ip4_to_decimal($ip4_net_addr) & $ip4_netmask;
		my $ip4_range_high = $ip4_range_low | ($ip4_netmask ^ 0xffffffff);

		$ret = ($key_ip4 >= $ip4_range_low and $key_ip4 <= $ip4_range_high) ? 1 : 0;
		return $ret ^ $negate;
        } elsif (($ip4_net_addr, my $prefix) = $match_str =~ "^($ip4_cidr_re)\$") {
		log_msg 2, "ip4 match is ip/prefix (cidr)";

		# invalid prefix results in 'not a match', regardless of comparator
		log_msg 0, "invalid prefix in ip4 match: $prefix" if $prefix > 32;
		return 0 if $prefix > 32;

		$key_ip4 = ip4_to_decimal $key_ip4;
		my $ip4_range_low = ip4_to_decimal $ip4_net_addr;
		my $bits_remaining = 32 - $prefix;
		my $ip4_range_high = $ip4_range_low + 2**$bits_remaining - 1;

		$ret = ($key_ip4 >= $ip4_range_low and $key_ip4 <= $ip4_range_high) ? 1 : 0;
		return $ret ^ $negate;
	}
	log_msg 0, "ip4 match didn't match any known format"; 

	return 0;
}

# testing the ip4 matching
my $ip = '192.168.122.73';
my @ip4_tests = (
	'ip4=*',
	'ip4!=*',

	'ip4=192.168.122.73',
	'ip4==192.168.122.73',
	'ip4!=192.168.122.73',
	'ip4!=192.168.122.75',

	'ip4=192.168.122.70-192.168.122.80',
	'ip4=192.168.122.0-192.168.122.58',
	'ip4!=192.168.122.70-192.168.122.80',
	'ip4!=192.168.122.0-192.168.122.58',

	'ip4=192.168.122.0/255.255.255.0',
	'ip4=192.168.12.0/255.255.0.0',
	'ip4=192.168.123.0/255.255.255.0',
	'ip4!=192.168.123.0/255.255.255.0',

	#invalid netmask?
	'ip4=192.168.122.0/255.255.0.255',


	'ip4=192.168.122.0/24',
	'ip4!=192.168.122.0/24',
	'ip4=192.168.122.0/32',
	'ip4=192.168.122.0/33' # invalid prefix
);
sub test_ip4_cases {
	foreach my $test_str (@ip4_tests) {
		if ((my $comparator, my $match_pattern) = $test_str =~ $ip4_comparison_re) {
			my $ret = check_ip4_match($ip, $comparator, $match_pattern);
			printf "%s  ->  %s\n", $test_str, $ret ? 'match' : 'no match';
		} else {
			printf "did not match regex!  %s\n", $test_str;
		}
	}
	exit;
}
# test_ip4_cases; # TODO: when satisfied with ip4 matching logic, remove this code



openlog($log_ident, 'ndelay,pid', 'daemon'); # or die "Could not open syslog: $!"; #?
log_msg 1, "$log_ident vers $helper_version";

if ($#ARGV ne 0) {
	log_msg 0, "USAGE: $0 <keyid>";
#	printf "USAGE: $0 <keyid>";
	exit -1;
}
$keyid = $ARGV[0];


# no config file?  just execute with default options
exec_upcall if (! -e $upcall_conf);

my $key_description_str = get_key_description $keyid;
if ($key_description_str !~ $key_description_re) {
	log_msg 0, "could not match key description to known format: $key_description_str";
	log_msg 1, "executing upcall with default parameters";
	exec_upcall;
}
my %vars;
($vars{'uid'}, $vars{'gid'}, $vars{'perms'}, $vars{'hostname'}, $vars{'ipv'}, $vars{'ip'},
	$vars{'sec'}, $vars{'uid2'}, $vars{'creduid'}, $vars{'username'}) = $key_description_str =~ $key_description_re;


$vars{'uid2'} = scalar POSIX::strtol($vars{'uid2'}, 16);
$vars{'creduid'} = scalar POSIX::strtol($vars{'creduid'}, 16);
log_msg 1, "description for key %d  uid: %d, gid: %d, perms: %d, hostname: %s, ipv: %s, ip: %s, sec: %s, uid2: %d, creduid: %d, username: %s",
	$keyid, $vars{'uid'}, $vars{'gid'}, $vars{'perms'},
	$vars{'hostname'}, $vars{'ipv'}, $vars{'ip'},
	$vars{'sec'}, $vars{'uid2'}, $vars{'creduid'}, $vars{'username'};


## open and read criteria file /etc/cifs-upcall.conf
open CONF, '<', $upcall_conf or die "Can't open $upcall_conf: $!";
while (<CONF>) {
	my $line = $_;
	chomp $line;

	next if ($line eq '' or substr($line, 0, 1) eq '#');

	if ($line !~ $conf_split_re) {
		log_msg 0, "unparseable line in $upcall_conf: $line";
		next;
	}
	my ($criteria_str, $opts_str) = $line =~ $conf_split_re;

	if ($criteria_str eq 'default' or $criteria_str eq 'defaults') {
		%upcall_opts = ();
		set_upcall_opts $opts_str;
		next;
	}

	my $match = 1;

	my @criterion_ary = split /$split_char/, $criteria_str;
	foreach my $criterion (@criterion_ary) {
		last if $match == 0;

		my ($field, $comparator, $match_pattern);

		if ($criterion eq '*') { next; } # '*' is always true
		elsif (($field, $comparator, $match_pattern) = $criterion =~ $string_comparison_re) {
			if ($field eq 'host') {
				$match = 0 if (! check_string_match($vars{'hostname'}, $comparator, $match_pattern));
			} elsif ($field eq 'user') {
				$match = 0 if (! check_string_match($vars{'username'}, $comparator, $match_pattern));
			} else { # ($field eq 'sec')
				$match = 0 if (! check_string_match($vars{'sec'}, $comparator, $match_pattern));
			}
		} elsif (($field, $comparator, $match_pattern) = $criterion =~ $uid_comparison_re) {
			if ($field eq 'uid') {
				$match = 0 if (! check_uid_match($vars{'uid2'}, $comparator, $match_pattern));
			} else { # ($field eq 'creduid')
				$match = 0 if (! check_uid_match($vars{'creduid'}, $comparator, $match_pattern));
			}
		} elsif (($comparator, $match_pattern) = $criterion =~ $ip4_comparison_re) {
			$match = 0 if (! check_ip4_match($vars{'ip'}, $comparator, $match_pattern));
#		} elsif (($field, $comparator, $match_pattern) = $criterion =~ $ip6_comparison_re) { # TODO: ip6
		} else {
			log_msg 0, "unrecognized match string: $criterion";
			$match = 0;
			last;
		}
	}
	if ($match) {
		log_msg 1, "matched '$criteria_str'";
		set_upcall_opts $opts_str; # similar to defaults, but don't clear first
		exec_upcall;
	}
}

log_msg 1, "no keyid matched; executing upcall with default parameters";
exec_upcall;
