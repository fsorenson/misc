#!/usr/bin/perl -w

use strict;
use warnings;

my %stacks = ();

my $pid_width = 25;

while(<>) {
	chomp;
	my $line = $_;


#	if ($line =~ /^ (.*<\.\.\.>-[0-9]+)(.+)/) { # these are misaligned, for some reason
#		$line = sprintf("%s%s", $1, $2);
#	}

	if ($line =~ /^([ ]*)(.+) (\[[0-9]+\]) (.+): (funcgraph_entry:) (.+)\|([ ]+)([0-9a-zA-Z_\.]+)( \[[a-zA-Z0-9_\.]+\])?\(\) \{/) {
#          fsperf-2257  [087] 443018.640870: funcgraph_entry:                   |  call_transmit() {
#          fsperf-2257  [084] 443018.617221: funcgraph_entry:        0.674 us   |  xprt_release_xprt();
#          fsperf-2257  [084] 443018.617228: funcgraph_entry:        0.053 us   |  xprt_reserve_xprt();
#          fsperf-2257  [084] 443018.617245: funcgraph_entry:        0.167 us   |  xprt_reserve_xprt();
#           <...>-172660 [084] 443018.617283: funcgraph_entry:        1.468 us   |  xprt_release_xprt();

		my $proc_pid = $2;
		my $cpu = $3;
		my $start_time = $4;
		my $funcgraph_entry = $5;
		my $stuff = $6;

		my $spaces = $7;

		my $func = $8;
		my $module = "";
		if (defined $9) {
			$module = $7;
		}
		my $func_mod = "$func$module";

		my $proc_name = "";
		my $pid = "";

		if ($proc_pid =~ /(.+)-([0-9]+)$/) {
			$proc_name = $1;
			$pid = $2;
		} else {
			$proc_name = "???";
			$pid = $proc_pid;
		}

		my %new_ele = ( 'func_mod' => $func_mod, 'start_time' => $start_time );

		printf("%*s %s %s: %s %s|%s%s() {\n", $pid_width, $proc_pid, $cpu, $start_time, $funcgraph_entry, $stuff, $spaces, $func_mod);

#		push @{$stacks{$pid}}, { 'func_mod' => $func_mod, 'start_time' => $start_time };
		push @{$stacks{$pid}}, \%new_ele;
	} elsif ($line =~ /([ ]*)(.+) (\[[0-9]+\]) (.+): (funcgraph_exit:) (.+)\|([ ]+)}$/) {
#		<...>-183870 [090] 443031.690628: funcgraph_exit:         4.788 us   |    }
		my $start_time = "";

		my $proc_pid = $2;
		my $proc_name = "";
		my $pid = "$proc_pid";
		my $cpu = $3;
		my $curr_time = $4;
		my $funcgraph_exit = $5;
		my $stuff = $6;
		my $spaces = $7;

		my $fn;

		if ($proc_pid =~ /(.+)-([0-9]+)$/) {
			$proc_name = $1;
			$pid = $2;
		}

		if (!defined($stacks{$pid})) {
			$stacks{$pid} = [];
		}
		#		printf("scalar \@{\$stacks{%d}} = %d\n", $pid, scalar @{$stacks{$pid}});

		if (scalar @{$stacks{$pid}} > 0) {
			my %fn_time;
			%fn_time = %{ pop @{$stacks{$pid}} };
			$fn = $fn_time{'func_mod'};
			$start_time = $fn_time{'start_time'};
		} else {
			$fn = "????";
		}


#		printf("%s complete\n", $fn);
#		<...>-183870 [090] 443031.690628: funcgraph_exit:         4.788 us   |    }
		printf("%*s %s %s: %s %s|%s} /* %s */\n", $pid_width, $proc_pid, $cpu, $curr_time, $funcgraph_exit, $stuff, $spaces, $fn);
	} elsif ($line =~ /([ ]*)(.+-[0-9]+) (.+)$/) {
#          <...>-43912 [226] 276690.582264: funcgraph_entry:        0.198 us   |  xprt_reserve_xprt();
		printf("%*s %s\n", $pid_width, $2, $3);
	} else {
		printf("%s\n", $line);
	}
}


#  0)               |          encode_fattr3.isra.2 [nfsd]() {
#  0)               |    schedule() {
#  0)               |                update_curr() {
#   <...>-57119   1dN...   336.122948: funcgraph_entry:                   |                                    __do_softirq() {
#   <...>-57119   1.Ns..   336.122948: funcgraph_entry:                   |                                      run_timer_softirq() {
#   <...>-57119   1.Ns..   336.122949: funcgraph_exit:         1.138 us   |                                      }
#   <...>-57119   1.Ns..   336.122950: funcgraph_entry:                   |                                      rcu_process_callbacks() {
#   <...>-57119   1.Ns..   336.122951: funcgraph_entry:                   |                                        __rcu_process_callbacks() {
#   <...>-57119   1.Ns..   336.122952: funcgraph_exit:         1.224 us   |                                        }
#   <...>-57119   1.Ns..   336.122952: funcgraph_entry:                   |                                        __rcu_process_callbacks() {

#   <...>-57119   1.....   336.126525: funcgraph_exit:       + 50.580 us  |                        }
#   <...>-57119   1.....   336.126525: funcgraph_exit:       + 52.514 us  |                      }
#   <...>-57119   1.....   336.126525: funcgraph_exit:       ! 278831.156 us |                    }
#   <...>-57119   1.....   336.126526: funcgraph_entry:                   |                    xfs_qm_sync() {
#   <...>-57119   1.....   336.126527: funcgraph_entry:                   |                      mutex_lock() {
#   <...>-57119   1.....   336.126527: funcgraph_entry:        0.270 us   |                        _cond_resched();
#   <...>-57119   1.....   336.126528: funcgraph_exit:         0.939 us   |                      }
