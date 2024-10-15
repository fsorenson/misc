#!/usr/bin/perl -w

use strict;
use warnings;

use Data::Dumper;


my $lock_file_name = "proc/locks";
my $mountinfo_file_name = "proc/self/mountinfo";
my $lsof_file_name = "lsof";


our %mountinfo = ();
my %pid_info = ();
my @lk_list = ();
my %dev_inode_info = ();

my $ultradebug = 0;

# proc/self/mountinfo
# lsof
# proc/locks

#16 58 0:16 / /sys rw,nosuid,nodev,noexec,relatime shared:6 - sysfs sysfs rw
#17 58 0:4 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
#18 58 0:6 / /dev rw,nosuid shared:2 - devtmpfs devtmpfs rw,size=8051080k,nr_inodes=2012770,mode=755
#19 16 0:17 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:7 - securityfs securityfs rw
#20 18 0:18 / /dev/shm rw,nosuid,nodev shared:3 - tmpfs tmpfs rw
#21 18 0:12 / /dev/pts rw,nosuid,noexec,relatime shared:4 - devpts devpts rw,gid=5,mode=620,ptmxmode=000
#22 58 0:19 / /run rw,nosuid,nodev shared:21 - tmpfs tmpfs rw,mode=755
#23 16 0:20 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:8 - tmpfs tmpfs ro,mode=755
#24 23 0:21 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:9 - cgroup cgroup rw,xattr,release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd
#25 16 0:22 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime shared:19 - pstore pstore rw
#26 23 0:23 / /sys/fs/cgroup/cpuset rw,nosuid,nodev,noexec,relatime shared:10 - cgroup cgroup rw,cpuset
#27 23 0:24 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:11 - cgroup cgroup rw,cpu,cpuacct
#28 23 0:25 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:12 - cgroup cgroup rw,memory
#29 23 0:26 / /sys/fs/cgroup/devices rw,nosuid,nodev,noexec,relatime shared:13 - cgroup cgroup rw,devices
#30 23 0:27 / /sys/fs/cgroup/freezer rw,nosuid,nodev,noexec,relatime shared:14 - cgroup cgroup rw,freezer
#31 23 0:28 / /sys/fs/cgroup/net_cls,net_prio rw,nosuid,nodev,noexec,relatime shared:15 - cgroup cgroup rw,net_cls,net_prio
#32 23 0:29 / /sys/fs/cgroup/blkio rw,nosuid,nodev,noexec,relatime shared:16 - cgroup cgroup rw,blkio
#33 23 0:30 / /sys/fs/cgroup/perf_event rw,nosuid,nodev,noexec,relatime shared:17 - cgroup cgroup rw,perf_event
#34 23 0:31 / /sys/fs/cgroup/hugetlb rw,nosuid,nodev,noexec,relatime shared:18 - cgroup cgroup rw,hugetlb
#55 16 0:32 / /sys/kernel/config rw,relatime shared:20 - configfs configfs rw
#58 0 253:1 / / rw,noatime shared:1 - ext4 /dev/mapper/root-root00 rw,dioread_nolock,data=ordered
#
#40 24 7:9 /usr/share /usr/share ro,relatime shared:25 - squashfs /dev/loop9 ro
#50 43 0:21 / /cAppCom/init.d rw,relatime shared:38 - nfs [2a00:da9:2:1270::105]:/dcsvsssh0105_cxp/sh_swhdo01n_cxp/lnx/rhel/cAppCom#init.d rw,vers=3,rsize=262144,wsize=262144,namlen=255,hard,nolock,proto=tcp6,timeo=600,retrans=2,sec=sys,mountaddr=2a00:da9:2:1270::105,mountvers=3,mountport=1234,mountproto=tcp6,local_lock=all,addr=2a00:da9:2:1270::105
sub parse_mountinfo {
	my $base_dir = shift;
	open(my $fh, $base_dir . "/" . "proc/self/mountinfo") or die("Could not open $base_dir/proc/self/mountinfo");
	while (<$fh>) {
		chomp;
		my $line = $_;

		if ($line =~ /^([0-9]+) ([0-9]+) (([0-9]+):([0-9]+)) ([^ ]+) ([^ ]+) ([^ ]+)* ([^ ]+ )?- ([^ ]+) ([^ ]+) ([^ ]+)/) {
			my $dev = $3;
			$dev =~ tr/:/,/;

			$mountinfo{$dev} = { 'dev' => $dev, 'mount_id' => $1, 'parent_id' => $2,
				'root' => $4, 'mountpoint' => $7, 'mount_opts' => $6,
				'optional_shared' => $9,
				'fs_type' => $10, 'mount_source' => $11, 'super_opts' => $12 };

#			printf("     fs_type=$10, mount_source=$11\n");
		} else {
			printf("***** parse_mountinfo: NO MATCH: '%s' *****\n", $line);

			if ($line =~ /^([0-9]+) ([0-9]+) (([0-9]+):([0-9]+)) ([^ ]+) ([^ ]+) ([^ ]+)* ([^ ]+ )?- ([^ ]+) ([^ ]+) ([^ ]+)/) {
				#      17       24       0:4                 /       /proc   rw,nosuid,nodev,noexec,relatime
				#                                                                    shared:30 - proc proc rw
				#      40       24       7:9                 /usr/share
				#                                                    /usr/share
				#                                                            ro,relatime
				#                                                                    shared:25 - squashfs /dev/loop9 ro
				printf("partially parsed\n");
			}
		}


	}
	close($fh);
}



#1: OFDLCK ADVISORY  WRITE -1 ca:50:33554699 0 EOF
#2: OFDLCK ADVISORY  READ  -1 00:09:6388338 0 EOF
#3: OFDLCK ADVISORY  READ  -1 00:09:44068 0 EOF
#4: OFDLCK ADVISORY  READ  -1 00:09:15070 0 EOF
#5: FLOCK  ADVISORY  WRITE 1960 ca:50:147 0 EOF
#6: OFDLCK ADVISORY  READ  -1 00:09:30530 0 EOF
#8: FLOCK  ADVISORY  WRITE 1414 fd:00:163578468 0 EOF
#9: OFDLCK ADVISORY  WRITE -1 ca:50:33554691 0 EOF
#10: POSIX  ADVISORY  WRITE 876 00:14:22805 0 EOF
#11: OFDLCK ADVISORY  WRITE -1 ca:50:33554693 0 EOF

sub parse_locks {
	my $base_dir = shift;
	open(my $fh, $base_dir . "/" . "proc/locks") or die("Could not open $base_dir/proc/locks");
	my $i = 0;

	while (<$fh>) {
		chomp;
		my $line = $_;

		if ($line =~ /^(.+) -> (.+)$/) {
			$line = sprintf("%s %s", $1, $2);
		}

		if ($line =~ /^([0-9]+): (FLOCK |POSIX |OFDLCK) (ADVISORY |MANDATORY|MSNFS    |[^ ]+) (READ |WRITE|NONE ) ([-0-9]+) ([0-9a-f]+):([0-9a-f]+):([0-9]+) ([0-9]+) ([0-9]+|EOF)/) {
			my $lk_num = $1;
			my $lk_desc = sprintf("%s:%s", $2, $3);
			my $lk_type = $4;
			my $pid = $5;
			my $mount_dev = sprintf("%d,%d", hex($6), hex($7));
			my $ino = $8;
			my $lk_start = $9;
			my $lk_end = $10;

#			$lk_list[$lk_num] = { 'desc' => $lk_desc, 'type' => $lk_type,
#				'pid' => $pid, 'dev' => $mount_dev, 'inode' => $ino,
#				'start' => $lk_start, 'end' => $lk_end };

			my $comm = "(unknown)";
			if (defined($pid_info{$pid}{'comm'})) {
				$comm = $pid_info{$pid}{'comm'};
			} else { }

			my $filename = "unknown";
			if (defined($dev_inode_info{$mount_dev}{$ino})) {
				$filename = $dev_inode_info{$mount_dev}{$ino}{'name'};
				# could also replace 'EOF' with file end/size from 'pos'
			} else {
#				$mount_dev = sprintf("%d:%d", hex($6), hex($7));
				if (defined($mountinfo{$mount_dev})) {
					$filename = sprintf("unknown - inode %d on mountpoint '%s'", $ino, $mountinfo{$mount_dev}{'mountpoint'});
				}
			}

			printf("%4d %15s %6d %-15s %5s %10d %10s %s\n",
				++$i, $comm, $pid, $lk_desc, $lk_type, $lk_start, $lk_end, $filename);
		} elsif ($line =~ /^([0-9]+): (LEASE)  (ACTIVE|BREAKING|BREAKER)[ ]+(READ |WRITE) ([0-9]+) ([0-9a-f]+):([0-9a-f]+):([0-9]+) ([0-9]+) ([0-9]+|EOF)/) {
			my $lk_num = $1;
			my $lk_desc = sprintf("%s:%s", $2, $3);
			my $lk_type = $4;
			my $pid = $5;
			my $mount_dev = sprintf("%d,%d", hex($6), hex($7));
			my $ino = $8;
			my $lk_start = $9;
			my $lk_end = $10;
#1: LEASE  ACTIVE    READ  2555 fd:11:66323391 0 EOF

			my $comm = "(unknown)";
			if (defined($pid_info{$pid}{'comm'})) {
				$comm = $pid_info{$pid}{'comm'};
			}

			my $filename = "unknown";
			if (defined($dev_inode_info{$mount_dev}{$ino})) {
				$filename = $dev_inode_info{$mount_dev}{$ino}{'name'};
				# could also replace 'EOF' with file end/size from 'pos'
			} else {
#				$mount_dev = sprintf("%d:%d", hex($6), hex($7));
				if (defined($mountinfo{$mount_dev})) {
					$filename = sprintf("unknown - inode %d on mountpoint '%s'", $ino, $mountinfo{$mount_dev}{'mountpoint'});
				}
			}

			printf("%4d %15s %6d %-15s %5s %10d %10s %s\n",
				++$i, $comm, $pid, $lk_desc, $lk_type, $lk_start, $lk_end, $filename);

		} else {
			printf("***** parse_locks: NO MATCH: '%s' *****\n", $line);
		}


	}
	close($fh);
}

my $ignore_file_types = "IPv4|IPv6|sock|unix|raw|unknown";
my $keep_file_types = "REG|DIR|CHR|FIFO|BLK|a_inode|netlink";
my $file_types = "$keep_file_types|$ignore_file_types";

sub parse_lsof {
	my $base_dir = shift;
	open(my $fh, $base_dir . "/" . "lsof") or die("Could not open $base_dir/lsof");

	my $hdr = <$fh>;

	my $has_tid = 0;

	return if (!defined($hdr));

	if ($hdr =~ /^COMMAND\s+PID\s+TID\s+USER\s+FD\s+TYPE\s+DEVICE\s+SIZE\/OFF\s+NODE\s+NAME$/) {
		$has_tid = 1;
	}

        while (<$fh>) {
		chomp;
		my $line = $_;
		my $details;
		my $fd;
		my $file_type;

		if ($line =~ /^([^\s]+)\s+([0-9]+)\s+(?:([0-9]+)\s+|)([0-9]+)\s+(.+)\s+($file_types)\s+(.+)$/) {
#systemd       1              0  mem       REG              253,1     155464    2490970 /usr/lib64/ld-2.17.so
#auditd    11721 11727        0  mem       REG              253,1     113584    2501812 /usr/lib64/libnsl-2.17.so
#auditd    11721 11727        0  mem       REG              253,1      42520    2491850 /usr/lib64/libwrap.so.0.7.6
#auditd    11721 11727        0  mem       REG              253,1     155464    2490970 /usr/lib64/ld-2.17.so
#auditd    11721 11727        0  mem       REG              253,1     228476    2501591 /usr/lib64/libnss_centrifydc.so.2
#auditd    11721 11727        0    0u      CHR                1,3        0t0       2052 /dev/null
#auditd    11721 11727        0    1u      CHR                1,3        0t0       2052 /dev/null
#auditd    11721 11727        0    2u      CHR                1,3        0t0       2052 /dev/null
#auditd    11721 11727        0    3u  netlink                           0t0      40792 AUDIT
#auditd    11721 11727        0    4w      REG              253,5    4575964    1179650 /var/log/audit/audit.log
#auditd    11721 11727        0    5u     unix 0xffff881ffe252400        0t0      40796 socket
#auditd    11721 11727        0    7u     unix 0xffff881ffe252000        0t0      40797 socket
#HostMonit 30329 30367        0  mem-W     REG              253,6       8816    1703991 /var/VRTSvcs/stats/.vcs_host_stats.index

			my $comm = $1;
			my $pid = $2;
			my $tid = $3;
			my $user = $4;
			$fd = $5;

			$file_type = $6;
			$details = $7;

#			to double-check or not to double-check...  that is the question
#			if ($fd =~ /^([0-9]+(?:[rwu](?:[ rRwWuU])|[-][ rRwWuU]|)|mem-r|mem|cwd|rtd|txt|DEL|a_inode|netlink)$/) {
#				# everything's copacetic
#			}

			if (! defined($pid_info{$pid})) {
				$pid_info{$pid} = { 'comm' => $comm, 'user' => $user };
			}

			if ($file_type =~ /^($ignore_file_types)$/) {
				next;
			}

			if ($fd =~ /^(txt|cwd|rtd)$/) {
				next;
			}
		} else {
			next;
		}

#			$fd = $1;
#			$details = $2;
#		} else {
#			printf("couldn't find fd in '%s' (line '%s')\n", $details, $line);
#			next;
#		}
#		if ($fd =~ /^(txt|cwd|rtd)$/) {
#			next;
#		}

#		my $file_type;
#		if ($details =~ /^(REG|DIR|IPv4|IPv6|CHR|FIFO|BLK|sock|unix|raw|a_inode|netlink)\s+(.+)$/) {
#			$file_type = $1;
#			$details = $2;
#		} else {
#			printf("couldn't find file type in '%s' (line '%s')\n", $details, $line);
#			printf("\tfd = %s\n", $fd);
#			next;
#		}
#		if ($file_type =~ /^(IPv4|IPv6|sock|unix|raw)$/) {
#			next;
#		}

		my $dev;
		if ($details =~ /^([^\s]+)\s+(.+)$/) {
			$dev = $1;
			$details = $2;
		} else {
			printf("couldn't separate dev & remainder: '%s'\n", $details);
			next;
		}

		if ($dev =~ /^unknown$/) {
			next;
		}


#		if ($details =~ /^(\w+)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+([0-9]+)\s+(.+)$/) {
	        if ($details =~ /^([0-9]+(?:t[0-9]+|))\s+(?:([0-9]+)\s+|)(.+)$/) {
#                                    0 
#                                                  4026532555 /proc/3175/net/rpc/nfsd.export/channel
			my $pos = $1;
			my $ino = defined($2) ? $2 : "";
			my $filename = $3;

#printf("'%s' => file_type = %s, dev = %s, pos = %s, ino = %s, filename = '%s'\n", $details, $file_type, $dev, $pos, $ino, $filename) if ($ultradebug);

#		if ($line =~ /^(\w+)\s([0-9]+)\s(\w+)\s(\w+)\s(\w+)\s(\w+)\s([0-9]+)\s([0-9]+)\s(.+)$/) {
#		if ($line =~ /^(\w+)\s+([0-9]+)\s+(\w+)\s+(\w+)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+([0-9]+)\s+(.+)$/) {
#		if ($line =~ /^([^\s]+)\s+([0-9]+)\s+(\w+)\s+(\w+)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+([0-9]+)\s+(.+)$/) {
#                                                             4u      REG                
#                                                                             0,3        0 
#                                                                                                   4026532555 /proc/3175/net/rpc/nfsd.export/channel

#			if (!($fd =~ /^([0-9]+)([rwu][RWrw]?)$/)) {
#			if (!($fd =~ /^(([0-9]+)([-rwu][ RWrw]?)|mem|mem-r)$/)) {
#printf("fd = '%s' isn't worth keeping?\n", $fd) if ($ultradebug);
#				next;
#				my $fdnum = $1;
#			}

			if ($ino eq "") {
				# for some types, (mmap) pos has no meaning... it's probably an inode instead
				# java      40841      529  mem-r     REG  253,5            1179650 /tmp/javasharedresources/C260M2A64P_webspherev85_1.6_64_wasmqm_G21
				if ($fd =~ /^(mem(|-r|-w))/) {
					$ino = $pos;
					$pos = 0;
				} else {
				}

				printf("line: '%s', details: '%s', pos: '%s', ino: '%s', filename: '%s'\n",
					$line, $details, $pos, $ino, $filename) if ($ultradebug);
			}

			if (! defined($dev_inode_info{$dev})) {
				$dev_inode_info{$dev} = ();
			}
			if (! defined($dev_inode_info{$dev}{$ino})) {
				printf("setting dev_inode_info{%s}{%d} to ('name' => %s, 'pos' => %s, 'type' => %s\n",
					$dev, $ino, $filename, $pos, $file_type) if ($ultradebug);
				$dev_inode_info{$dev}{$ino} = { 'name' => $filename, 'pos' => $pos, 'type' => $file_type };
			} else {
				printf("dev_inode_info{%s}{%s} is already set?\n",
					$dev, $ino) if ($ultradebug);
			}
		} else {
#		        if ($line =~ /^([^\s]+)\s+([0-9]+)\s+(\w+)\s+(\w+)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+([0-9]+)\s+(.+)$/) {
#		        if ($line =~ /^(\w+)\s+(\w+)\s+([^\s]+)\s+(.+)$/) {
		        if ($details =~ /^(\w+)\s+(\w+)\s+([^\s]+)\s+([0-9]+)\s+(.+)$/) {
				printf("fd=%s, ftype=%s, dev=%s, size/off=%d, rest=%s\n", $1, $2, $3, $4, $5);
#(\w+)\s+(\w+)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+([0-9]+)\s+(.+)$/) {
#			} else { printf("still couldn't parse lsof: %s\n", $line); }
#			} else { printf("still couldn't parse lsof: %s\n", $details); }
			} else { }

#		couldn't parse lsof: smbd      29706        0  mem-r     REG              253,0 18178048     264463 /var/lib/samba/locking.tdb
			printf("couldn't parse lsof: %s\n", $line);
			printf("\tdetails='%s'\n", $details);

		}
	}
	close($fh);
#print Dumper \%pid_info;
#print Dumper \%dev_inode_info;

}

# if no directories are given on command-line, use the current directory
push(@ARGV, ".") if (scalar(@ARGV) == 0);

foreach my $dir (@ARGV) {
	# empty out our hashes for each new root directory
	%mountinfo = ();
	%pid_info = ();
	@lk_list = ();
	%dev_inode_info = ();

	parse_mountinfo($dir);
	#printf("dumping...\n");
	#print Dumper \%mountinfo;
	parse_lsof($dir);
	parse_locks($dir);

	#print Dumper \%dev_inode_info;
}
