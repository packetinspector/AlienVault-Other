#!/usr/bin/perl

use Munin::Plugin;

my $tail_cmd = 'tail -100 /var/log/ossim/agent.log | grep Total | tac';
#
my $config = $ARGV[0] && $ARGV[0] eq "config";
my $tail_output = `$tail_cmd`;
my $mark = 0;
my @lines = split(/\n/,$tail_output);


if ($config) {
	print "graph_title Plugin EPS\n";
	print "graph_info EPS Per Plugin.\n";
	print "graph_vlabel EPS\n";
	print "graph_scale no\n";
	#exit 0;
}

foreach my $line (@lines) {
	#print "Line: $line\n";
	if ($mark == 0 && $line =~ /Total events captured/) {
		#print "Start Found\n";
		$mark = 1;
		next;
	}
	if ($line =~ /Total events captured/ && $mark == 1) {
		#print "All Done\n";
		last;
	}
	if ($line =~ /Plugin\[(\d+)\].*?EPS:\s+\[([\d\.]+)\]/ && $mark == 1) {
		#print "Plugin: $1 EPS: $2\n";
		#Munin seems to really want labels....
		if ($config) {
			print "$1.label $1\n";
			print "$1.draw AREASTACK\n";
		} else {
			print "$1.value $2\n";
		}
	}
}
exit 0;
