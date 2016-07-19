#!/usr/bin/perl -w

use strict;
use warnings;

my @stack = ();

while(<>) {
	chomp;
	my $line = $_;

	if ($line =~ /(.+) \|([ ]+)([0-9a-zA-Z_\.]+)( \[[a-zA-Z0-9_\.]+\])?\(\) \{/) {
		my $func = $3;
		my $module = "";
		if (defined $4) {
			$module = $4;
		}
		my $result = "$func$module";
		printf("%s |%s%s() {\n", $1, $2, $result);
#		printf("function start '%s' in '%s' (indent = %d)\n", $result, $line, length($2));
		push @stack, $result;
	} elsif ($line =~ /(.+) \|([ ]+)}$/) {
#		printf("function complete '%s' in '%s' (indent = %d)\n", $1, $line, length($2));
		my $fn;
		if ($#stack > -1) {
			$fn = pop @stack;
		} else {
			$fn = "???";
		}
#		printf("%s complete\n", $fn);
		printf("%s |%s} /* %s */\n", $1, $2, $fn);
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
