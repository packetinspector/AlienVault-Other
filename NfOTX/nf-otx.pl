#!/usr/bin/perl -w

#Uses nfdump and looks for matches in otx
#This is alpha and rudimentary.  Could use minimum otx thresholds and other stuff?
#Warranty? Nope. Guarantees? Nope.
# v .3 changed rep path and added bounds thanks @ritter6281
# v .4 fixed rec separator thanks @cdemerstremblay

use strict;
use IO::File;
use DateTime;
use Sys::Syslog;
#Using syslog to make logs, you could move to Net::Syslog and send these logs anywhere
openlog('nfotx', "local0");

#Debug 1 or 0
my $debug = 0;

#Polling interval.  Usually equal to watchdog interval (in minutes)
my $pi = 3;


#Set some vars
#stats file is smaller...
my $ip_repfile =  '/etc/ossim/server/reputation.data';

#You may want to extend this directory lower to a specific collector.  You probably don't want to run this against netflow from perimeter for instance
my $nfdir = '/var/cache/nfdump/flows/live';


#Make a polling date for nfdump to check
my $nfdump_check_time = DateTime->now(time_zone=> "local")->subtract( minutes => $pi)->strftime("%Y/%m/%d.%H:%M:%S");
my $nfdump_check_now = DateTime->now(time_zone=> "local")->strftime("%Y/%m/%d.%H:%M:%S");

#Open the OTX DB
my $fh = IO::File->new($ip_repfile, O_RDONLY) or die 'Could not open file ', $ip_repfile, ": $!";

#Build cmd
my $nf_dump_cmd = "/usr/bin/nfdump -R '$nfdir' -q -N -m -A srcip,dstip -t '$nfdump_check_time-$nfdump_check_now' -o extended";

#Run it into a FH
open (NFDUMP, "-|", $nf_dump_cmd) or die "Error Running NFDump";

#Initialize a hash to check for dupes, keep count for first match reference
my %dupes;
my $i = 0;

#Put file in array. Normally I'd do this in the while loop but it wasn't splitting right
my @nfoutput = <NFDUMP>;

while (my $line = pop @nfoutput) {
	chomp $line;
	
	my @fields = split(/\ +/, $line);
	#Grab source, only checking one source since flows are bi-directional
	my ($src_ip,$src_port) = split(':',$fields[4]);
	
	#Skip iteration if IP is local kinda of a lazy match for now...
	next if ($src_ip =~ m/^(192.168|172.16|10.|0.0.0.0)/);
	
	#Skip if checked already
	next if exists $dupes{$src_ip};
	
	#Add to dupes to avoid checking again
	$dupes{$src_ip} = $i;
	
	#Now search
	seek($fh,0,0);
	#stats file has quotes around IP so do we
	IO::File->input_record_separator($src_ip);
	$fh->getline;  #fast forward to the first match
	if ($fh->getline) {
		print "$src_ip Matched\n" if $debug;
		#Hey we matched, send the line to syslog
		syslog("info", $line);
		
	} else {
		print "$src_ip No Match\n" if $debug;
	}
	$i++;
}

#Be nice and close all the handles
$fh->close;
close(NFDUMP);
