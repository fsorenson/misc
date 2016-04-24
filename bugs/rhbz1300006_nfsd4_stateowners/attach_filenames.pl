#!/usr/bin/perl -w
#
# Frank Sorenson <sorenson@redhat.com>, 2016
#
# attach nfs v4 open information with failed open calls
#
# tshark -o 'nfs.file_name_snooping: TRUE' -o 'nfs.file_full_name_snooping: TRUE' -o 'nfs.fhandle_find_both_reqrep: TRUE' -z 'proto,colinfo,rpc.auth.machinename,rpc.auth.machinename' -z 'proto,colinfo,nfs.full_name,nfs.full_name' -z 'proto,colinfo,frame.number,frame.number' -z 'proto,colinfo,rpc.auth.uid,rpc.auth.uid' -z 'proto,colinfo,rpc.auth.gid,rpc.auth.gid' -R 'nfs.procedure_v4 && (nfs.opcode == 18)' | ./attach_filenames.pl
#

use strict;

my %call_info = ();
while (<>) {
	chomp;
	my $line = $_;

	if ($line =~ /V4 Call OPEN/) {
		my ($frame_num, $info);

		$info = $1 if ($line =~ /OPEN DH:(.+)$/);
		$frame_num = $1 if ($line =~ /frame.number == ([0-9]+) /);

		$call_info{$frame_num} = $info if ($frame_num && $info);
	} elsif ($line =~ /V4 Reply.+OPEN (Status|StateID):/) {
		my ($frame_num, $call_frame, $result);

		$frame_num = $1 if ($line =~ /frame.number == ([0-9]+)/);
		$call_frame = $1 if ($line =~ /\(Call In ([0-9]+)\)/);
		$result = $1 if ($line =~ /OPEN Status: (NFS4ERR_[A-Z]+)/);

		if ($result) { # failure
			my $call = "UNKNOWN";
			$call = $call_info{$call_frame} if (defined $call_info{$call_frame});

			printf "frame %d has a failure of call in frame %d: %s (call: %s)\n", $frame_num, $call_frame, $result, $call;
		}
		undef $call_info{$call_frame};
	}
}




