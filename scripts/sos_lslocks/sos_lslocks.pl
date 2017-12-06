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
	open(my $fh, "proc/self/mountinfo") or die("Could not open proc/self/mountinfo");
	while (<$fh>) {
		chomp;
		my $line = $_;

		if ($line =~ /^([0-9]+) ([0-9]+) (([0-9]+):([0-9]+)) ([^ ]+) ([^ ]+) ([^ ]+)* ([^ ]+ )?- ([^ ]+) ([^ ]+) ([^ ]+)/) {

			$mountinfo{$3} = { 'dev' => $3, 'mount_id' => $1, 'parent_id' => $2,
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

sub parse_locks {
	open(my $fh, "proc/locks") or die("Could not open proc/locks");
	my $i = 0;

	while (<$fh>) {
		chomp;
		my $line = $_;

		if ($line =~ /^([0-9]+): (FLOCK|POSIX)  (ADVISORY |MANDATORY|[^ ]+) (READ |WRITE) ([0-9]+) ([0-9a-f]{2}):([0-9a-f]{2}):([0-9]+) ([0-9]+) ([0-9]+|EOF)/) {
				my $lk_num = $1;
				my $lk_desc = sprintf("%s:%s", $2, $3);
				my $lk_type = $4;
				my $pid = $5;
				my $mount_dev = sprintf("%d,%d", hex($6), hex($7));
				my $ino = $8;
				my $lk_start = $9;
				my $lk_end = $10;


#				$lk_list[$lk_num] = { 'desc' => $lk_desc, 'type' => $lk_type,
#					'pid' => $pid, 'dev' => $mount_dev, 'inode' => $ino,
#					'start' => $lk_start, 'end' => $lk_end };


				my $comm = "(unknown)";
				if (defined($pid_info{$pid}{'comm'})) {
					$comm = $pid_info{$pid}{'comm'};
				}

				my $filename = "unknown";
				if (defined($dev_inode_info{$mount_dev}{$ino})) {
					$filename = $dev_inode_info{$mount_dev}{$ino}{'name'};
					# could also replace 'EOF' with file end/size from 'pos'
				}

				printf("%4d %15s %5d %5s %5s %10d %10s %s\n",
					++$i, $comm, $pid, $lk_desc, $lk_type, $lk_start, $lk_end, $filename);
		} else {
			printf("***** parse_locks: NO MATCH: '%s' *****\n", $line);
		}


	}
	close($fh);
}


sub parse_lsof {
	open(my $fh, "lsof") or die("Could not open lsof");
        while (<$fh>) {
		chomp;
		my $line = $_;

#		if ($line =~ /^(\w+)\s([0-9]+)\s(\w+)\s(\w+)\s(\w+)\s(\w+)\s([0-9]+)\s([0-9]+)\s(.+)$/) {
#		if ($line =~ /^(\w+)\s+([0-9]+)\s+(\w+)\s+(\w+)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+([0-9]+)\s+(.+)$/) {
		if ($line =~ /^([^\s]+)\s+([0-9]+)\s+(\w+)\s+(\w+)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+([0-9]+)\s+(.+)$/) {
			my $file_type = $5;
			if ($file_type ne "REG") {
#				printf("file type %s is not 'REG'\n", $file_type);
				next;
			}

			my $comm = $1;
			my $pid = $2;
			my $user = $3;
			my $fd = $4;
			my $dev = $6;
			my $pos = $7;
			my $ino = $8;
			my $filename = $9;

			if (!($fd =~ /^([0-9]+)([rwu][RWrw]?)$/)) {
				next;
#				my $fdnum = $1;
			}

			if (! defined($pid_info{$pid})) {
				$pid_info{$pid} = { 'comm' => $comm, 'user' => $user };
			}


			if (! defined($dev_inode_info{$dev})) {
				$dev_inode_info{$dev} = ();
			}
			if (! defined($dev_inode_info{$dev}{$ino})) {
				$dev_inode_info{$dev}{$ino} = { 'name' => $filename, 'pos' => $pos };
			}
		} else {
#			printf("couldn't parse %s\n", $line);
		}
	}
	close($fh);
#print Dumper \%pid_info;
#print Dumper \%dev_inode_info;

}

parse_mountinfo();
#printf("dumping...\n");
#print Dumper \%mountinfo;

parse_lsof();

parse_locks();





