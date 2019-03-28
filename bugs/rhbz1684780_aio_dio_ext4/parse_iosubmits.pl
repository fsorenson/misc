#!/usr/bin/perl -w

use strict;
use warnings;

use Data::Dumper;

my $range_min = (131072 * 512);
my $range_max = ($range_min + 512);

sub min {
	my $a = shift;
	my $b = shift;

	return $a < $b ? $a : $b;
}
sub max {
	my $a = shift;
	my $b = shift;

	return $a > $b ? $a : $b;
}

sub is_in_range {
	my $offset = shift;
	my $count = shift;

	my $buf_range_low = max($offset, $range_min);
	my $buf_range_high = min($offset + $count, $range_max);
	my $buf_range_len = $buf_range_high - $buf_range_low;

	if ($buf_range_len > 0) {
		return 1;
	}
	return 0;
}

sub elab_hexcolon_to_hexval {
	my $val = shift;

	$val =~ s/\s+$//;
	return join("", map {chr hex} split(":", $val));
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


while (<>) {
#	chomp;
	my $line = $_;
	$line =~ s/\n$//g;

#	printf("*$line*\n");
#	next;

	my @matches;
	my @fields;

	if (@matches = $line =~ /^(([0-9]+) ([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) )*io_submit\(([0-9]+), ([0-9]+), \[(.+)\]\) = ([0-9]+)( <[0-9]+.[0-9]{6}>)*$/) {
		# ioctx, iovec_count, iovecs, return
		my $ioctx = $matches[3];
		my $iovec_count = $matches[4];
		my $iovecs_str = $matches[5];
		my $retval = $matches[6];

		printf("io_submit: %s, return val: %d, iovecs:\n", $iovec_count, $retval);
#		printf("    %s\n", $iovecs_str);
#		while (@matches = $iovecs =~ /(\{data=(0x[0-9a-f]+), ([^,]+), fildes=([0-9]+), (buf=0x[0-9a-f]+|str=".+), nbytes=(0-9]+), offset=(0-9]+)\})(, \{. +\})?$/) {
#		while (@matches = $iovecs =~ /(\{data=.+\})(, \{.+\})?$/) {
#		while (@matches = $iovecs =~ /(\{data=.+\})(, \{.+\})?$/) {
		my @iovecs = ();
		my $iovec_num = $iovec_count;
		while (@matches = $iovecs_str =~ /(.*, )*(\{.+?\})$/) {
#			printf("  iovec %d:\n", $iovec_num);
#			printf("\tmatch 0: %s\n", $matches[0]) if (defined($matches[0]));
#			printf("\tmatch 1: %s\n", $matches[1]);
#			printf("\tmatch 2: %s\n", $matches[2]) if (defined($matches[2]));
			unshift @iovecs, $matches[1];
			if (!defined($matches[0])) {
				last;
			}
			$matches[0] =~ s/(.+), $/$1/;
			$iovecs_str = $matches[0];
			$iovec_num--;
#			printf("      remainder: %s\n", $iovecs_str);
		}
		for my $iovec (@iovecs) {
			if (@matches = $iovec =~ /\{data=(0x[0-9a-f]+), (.+), fildes=([0-9]+(<[^>]+>)*), (buf=0x[0-9a-f]+|str=".+), nbytes=([0-9]+), offset=([0-9]+)\}$/) {
#        iovec match 0: 0x7f1a9b1d41a8
#        iovec match 1: pread
#        iovec match 2: 260
#        iovec match 4: buf=0x7f1a9afb2000
#        iovec match 5: 1048Argument "buf=0x7f1a9afb2000"

				my $in_range = is_in_range($matches[6], $matches[5]);
				printf("\tsubmit iocb: %s, file descriptor: %d, operation: %s, offset: %s, length: %s - %sin range\n",
					$matches[0], $matches[2], $matches[1], $matches[6], $matches[5], $in_range ? "" : "not ");
			}
		}
	} elsif (@matches = $line =~ /^(([0-9]+) ([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) )*io_getevents\(([0-9]+), ([0-9]+), ([0-9]+), \[([^\]]+)\], \{([0-9]+, [0-9]+)\}\) = ([0-9]+)(| <[0-9]+\.[0-9]{6}>)$/) {

#for (my $zz = 0 ; $zz < 15 ; $zz++) {
#printf("\tgetevents match %d: %s\n", $zz, $matches[$zz]) if (defined($matches[$zz]));
#}
		printf("io_getevents(min=%d, max=%d, timeout: {%s}, result: %d\n",
			$matches[4], $matches[5], $matches[7], $matches[8]);
		#(139752355237888, 7, 128, [{data=0x7f1a9b1d51f8, obj=0x7f1a9b1d51f8, res=1048576, res2=0}, {data=0x7f1a9b1d54b0, obj=0x7f1a9b1d54b0, res=1048576, res2=0}, {data=0x7f1a995b1ca8, obj=0x7f1a995b1ca8, res=1048576, res2=0}, {data=0x7f1a9b1d5768, obj=0x7f1a9b1d5768, res=1048576, res2=0}, {data=0x7f1a9b1d5a20, obj=0x7f1a9b1d5a20, res=1048576, res2=0}, {data=0x7f1a9b1d5cd8, obj=0x7f1a9b1d5cd8, res=1048576, res2=0}, {data=0x7f1a995b1f60, obj=0x7f1a995b1f60, res=1048576, res2=0}], {0, 0}) = 7 <0.000011>

		my @iocbs = ();
		my $iocbs_str = $matches[6];

#		while (@matches = $iocbs_str =~ /(.*, )*(\{data=(0x[0-9a-f]+), obj=(0x[0-9a-f]+), res=([0-9]+), res2=([0-9]+)\})/) {
		while (@matches = $iocbs_str =~ /(.*, )*(\{data=0x[0-9a-f]+, obj=0x[0-9a-f]+, res=[0-9]+, res2=[0-9]+\})/) {
			unshift @iocbs, $matches[1];
			if (!defined($matches[0])) {
				last;
			}
			$iocbs_str = $matches[0];
		}
		my $iocb_num = 0;
		for my $iocb (@iocbs) {
#			print("parsed iocb\n");


			if (@matches = $iocb =~ /\{data=(0x[0-9a-f]+), obj=(0x[0-9a-f]+), res=([0-9]+), res2=([0-9]+)\}/) {
if (0) {
for (my $zz = 0 ; $zz < 15 ; $zz++) {
printf("\tmatch %d: %s\n", $zz, $matches[$zz]) if (defined($matches[$zz]));
}
}

#				fildes=([0-9]+(<[^>]+>)*), (buf=0x[0-9a-f]+|str=".+), nbytes=([0-9]+), offset=([0-9]+)\}$/) {
				printf("\tgetevents iocb %d - %s - result: %d\n",
					$iocb_num, $matches[1], $matches[2]);
			} else {
				printf("\t%d - could not parse iocb: %s\n",
					$iocb_num, $iocb);
			}
			$iocb_num++;
		}
#	} elsif (@matches = $line =~ /^(([0-9]+) ([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) )*ftruncate\(([0-9]+)(|<[^>]+), ([0-9]+)\) .*= ([0-9]+)(| <[0-9]+\.[0-9]{6}>)$/) {
	} elsif (@matches = $line =~ /^(([0-9]+) ([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) )*ftruncate\(([0-9]+)(|<[^>]+>), ([0-9]+)\) .*= ([0-9]+)(| <[0-9]+\.[0-9]{6}>)$/) {
#		94977 07:23:54.824592 ftruncate(10</backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1>, 67109376) = 0 <0.000018>
#		94977 07:26:15.458305 ftruncate(11</backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1>, 3812868608) = 0 <0.000272>

		printf("ftruncate - fd: %d (%s), len: %d, ret: %d\n", $matches[3], $matches[4], $matches[5], $matches[6]);
#	} elsif (
#		ftruncate(11</backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1>, 3812868608) = 0
	} elsif (@matches = $line =~ /^(([0-9]+) ([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) )*fsync\(([0-9]+)(|<[^>]+>)\) .*= ([0-9]+)(| <[0-9]+\.[0-9]{6}>)$/) {
		printf("fsync - fd: %d (%s), ret: %d\n", $matches[3], $matches[4], $matches[5]);

	} elsif (@matches = $line =~ /^(([0-9]+) ([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) )*close\(([0-9]+)(|<[^>]+>)\) .*= ([0-9]+)(| <[0-9]+\.[0-9]{6}>)$/) {
		printf("close - fd: %d (%s), ret: %d\n", $matches[3], $matches[4], $matches[5]);
	} elsif (@matches = $line =~ /^(?:([0-9]+) ([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) )*fstat\(([0-9]+)(?:|<([^>]+)>), (.+?)\) .*?= ([0-9]+|-1 E.+?)(?:| <([0-9]+\.[0-9]{6})>)$/) {
#        fstat match 0: 94977
#        fstat match 1: 07:23:54.811080
#        fstat match 2: 10
#        fstat match 3: /backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1
#        fstat match 4: {st_dev=makedev(253, 2), st_ino=216924547, st_mode=S_IFREG|0640, st_nlink=1, st_uid=502, st_gid=202, st_blksize=4096, st_blocks=0, st_size=0, st_atime=2019/02/27-07:23:54.810262097, st_mtime=2019/02/27-07:23:54.810262097, st_ctime=2019/02/27-07:23:54.810262097}
#        fstat match 5: 0
#        fstat match 6: 0.000010

		my $filename = "?";
		$filename = $matches[3] if (defined($matches[3]));
		printf("fstat %s (%s), ret: %s\n", $matches[2], $filename, $matches[5]);
	} elsif (@matches = $line =~ /^(?:([0-9]+) ([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) )*stat\("([^"]+)", (.+)\) .*= ([0-9]+|-1 E.+?)(?:| <([0-9]+\.[0-9]{6})>)$/) {
#        stat match 0: 94977
#        stat match 1: 07:23:54.810921
#        stat match 2: /backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1
#        stat match 3: 0x7fff7da1be68
#        stat match 4: -1 ENOENT (No such file or directory)
#        stat match 5: 0.000011

		printf("stat %s, ret: %s\n", $matches[2], $matches[4]);
	} elsif (@matches = $line =~ /^(([0-9]+) ([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) )*fstatfs\(([0-9]+)(|<[^>]+>), (\{.+\})\) = ([0-9]+|-1 E.+)(| <[0-9]+\.[0-9]{6}>)$/) {
#        fstatfs match 0: 94977 07:23:54.811140
#        fstatfs match 1: 94977
#        fstatfs match 2: 07:23:54.811140
#        fstatfs match 3: 10
#        fstatfs match 4: </backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1>
#        fstatfs match 5: {f_type=EXT2_SUPER_MAGIC, f_bsize=4096, f_blocks=7180236794, f_bfree=1635285659, f_bavail=1635281563, f_files=450560000, f_ffree=450504465, f_fsid={248511917, 4024781346}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOSUID|ST_NODEV|ST_NOEXEC|ST_NOATIME}
#        fstatfs match 6: 0
#        fstatfs match 7:  <0.000012>


#		^\}]+\}), f_namelen=([0-9]+), f_frsize=([0-9]+), f_flags=([
#		"([^"]+)", (.+)\) .*= ([0-9]+|-1 E.+)(| <[0-9]+\.[0-9]{6}>)$/) {

# 94977 07:23:54.811140 fstatfs(10</backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1>, {f_type=EXT2_SUPER_MAGIC, f_bsize=4096, f_blocks=7180236794, f_bfree=1635285659, f_bavail=1635281563, f_files=450560000, f_ffree=450504465, f_fsid={248511917, 4024781346}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOSUID|ST_NODEV|ST_NOEXEC|ST_NOATIME}) = 0 <0.000012>
		printf("fstatfs %d (%s), ret: %d\n", $matches[3], $matches[4], $matches[6]);
	} elsif (@matches = $line =~ /^(([0-9]+) ([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) )*statfs\("([^"]+)", \{(.+)\}\) = ([0-9]+|-1 E.+)(| <[0-9]+\.[0-9]{6}>)$/) {
# no match - 94977 07:23:54.825208 statfs("/backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1", {f_type=EXT2_SUPER_MAGIC, f_bsize=4096, f_blocks=7180236794, f_bfree=1635285128, f_bavail=1635281032, f_files=450560000, f_ffree=450504465, f_fsid={248511917, 4024781346}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOSUID|ST_NODEV|ST_NOEXEC|ST_NOATIME}) = 0 <0.000013>
#        statfs match 0: 94977 07:23:54.825208 
#        statfs match 1: 94977
#        statfs match 2: 07:23:54.825208
#        statfs match 3: /backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1
#        statfs match 4: f_type=EXT2_SUPER_MAGIC, f_bsize=4096, f_blocks=7180236794, f_bfree=1635285128, f_bavail=1635281032, f_files=450560000, f_ffree=450504465, f_fsid={248511917, 4024781346}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_NOSUID|ST_NODEV|ST_NOEXEC|ST_NOATIME
#        statfs match 5: 0
#        statfs match 6:  <0.000013>
		printf("statfs '%s', ret: %d\n", $matches[3], $matches[5]);
	} elsif (@matches = $line =~ /^(?:([0-9]+) ([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) )*open\("([^"]+)", ([A-Z_\| ]+)(?:|, ([0-9]+))\) = (?:([0-9]+)(?:|<([^>]+)>)|-1 E.+)(?:| <([0-9]+\.[0-9]{6})>)$/) {
# 94977 07:23:54.810964 open("/backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1", O_RDWR|O_CREAT|O_EXCL|O_SYNC, 0660) = 10</backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1> <0.000036>
#        open match 0: 94977
#        open match 1: 07:23:54.810964
#        open match 2: /backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1
#        open match 3: O_RDWR|O_CREAT|O_EXCL|O_SYNC
#        open match 4: 0660
#        open match 5: 10
#        open match 6: /backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1
#        open match 7: 0.000036

#        open match 0: 94977
#        open match 1: 07:23:54.811222
#        open match 2: /backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1
#        open match 3: O_RDWR|O_SYNC|O_DIRECT
#        open match 5: 10
#        open match 6: /backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1
#        open match 7: 0.000012

# 94977 07:23:54.825062 open("/backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1", O_RDONLY) = 10</backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1> <0.000011>
#        open match 0: 94977
#        open match 1: 07:23:54.825062
#        open match 2: /backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1
#        open match 3: O_RDONLY
#        open match 5: 10
#        open match 6: /backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1
#        open match 7: 0.000011
		if (defined($matches[4])) { # 3-argument open
			printf("open '%s', flags: %s, mode: %s, ret: %s\n",
				$matches[2], $matches[3], $matches[4], $matches[5]);
		} else {
			printf("open '%s', flags: %s, ret: %s\n",
				$matches[2], $matches[3], $matches[5]);
		}

	} elsif (@matches = $line =~ /^(([0-9]+) ([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) )*pwrite64\(([0-9]+)(|<[^>]+>), "(.+)", ([0-9]+), ([0-9]+)\) .*= ([0-9]+)(| <[0-9]+\.[0-9]{6}>)$/) {
		printf("pwrite - fd: %d (%s), offset: %d, length: %d, ret: %d\n",
			$matches[3], $matches[4], $matches[7], $matches[6], $matches[8]);
	} elsif (@matches = $line =~ /^(?:([0-9]+) ([0-9]{2}:[0-9]{2}:[0-9]{2}.[0-9]{6}) )*pread64\(([0-9]+)(?:|<([^>]+)>), "(.+)", ([0-9]+), ([0-9]+)\) .*= ([0-9]+)(?:| <([0-9]+\.[0-9]{6})>)$/) {
# 94977 07:23:54.825370 pread64(10</backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1>, "...", 512, 0) = 512 <0.001315>
#        pread match 0: 94977
#        pread match 1: 07:23:54.825370
#        pread match 2: 10
#        pread match 3: /backup/db/online/trc_bkp/ora_OSS_1001316234_s33205_p1
#        pread match 4: ...
#        pread match 5: 512
#        pread match 6: 0
#        pread match 7: 512
#        pread match 8: 0.001315

if (0) {
for (my $zz = 0 ; $zz < 15 ; $zz++) {
printf("\tfstat match %d: %s\n", $zz, $matches[$zz]) if (defined($matches[$zz]));
}
}

		my $filename = "?";
		$filename = $matches[3] if (defined($matches[3]));
		printf("pread - fd: %d (%s), offset: %d, length: %d, ret: %s\n",
			$matches[2], $filename, $matches[6], $matches[5], $matches[7]);
	} elsif ($line eq "") { # empty line... just pass it through
		printf("\n");
	} else {
		printf("no match - %s\n", $line);
	}
}



#	match 1: {data=0x7f292ddd2820, pwrite, fildes=7, str="\25\302\0\0\1\0\0\0\0\0\0\0\0\0\1\4\262\275\0\0\0\0\0\0\0\0\0\22\331\215_;"..., nbytes=16384, offset=16384}
#parsed iovec:
#	0: 0x7f292ddd2820
#	1: pwrite
#	2: 7
#	3: str="\25\302\0\0\1\0\0\0\0\0\0\0\0\0\1\4\262\275\0\0\0\0\0\0\0\0\0\22\331\215_;"...
#	4: 16384
#	5: 16384
#file descriptor: 0, operation: pwrite, offset: 7, length: 16384
#parsed iovec:
#	0: 0x7f292ddd2d50
#	1: pwrite
#	2: 9
#	3: str="\25\302\0\0\1\0\0\0\0\0\0\0\0\0\1\4\262\275\0\0\0\0\0\0\0\0\0\22\331\215_;"...
#	4: 16384
#	5: 16384


#./parse_iosubmits.pl <z | grep -vf read_iocbs | egrep 'submit iocb|getevents iocb' | awk '{if ($1=="submit") {outstanding++} else {outstanding--} ; printf("%d\n", outstanding)} END{printf("remaining outstanding: %d\n", outstanding)}'
