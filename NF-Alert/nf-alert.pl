#!/usr/bin/perl
# NF-Alert
# Makes events for network traffic
# Perhaps this will do more.  Right now it looks for large uploads and downloads
use DateTime;
use Date::Parse;
use Getopt::Std;
use Sys::Syslog;
use POSIX;
#
use vars qw/ %opt /;

use Data::Dumper;
$Data::Dumper::Indent = 3; 
###########################################User Config Stuff

#You may want to extend this directory lower to a specific collector.  You probably don't want to run this against netflow from perimeter for instance
my $nfdir = '/var/cache/nfdump/flows/live';
#Nfdump notation: 25 Megs
my $min_download_size = '+8M'; #in-line with alert hash below
my $min_upload_size = '+25M'; #in-line with alert hash below
#Alert Thresholds (if you change these remake the SQL...)
#[num_of_bytes] => [ [sid], [message] ]
my %download_alerts = ( 800000 => [99, 'Network Download greater than 8M'], 25000000 => [100, 'Network Download greater than 25M'], 100000000 => [101, 'Network Download greater than 100M'] );
my %upload_alerts = ( 25000000 => [200, 'Network Upload greater than 25M'], 100000000 => [201, 'Network Upload greater than 100M'] );
#Netflow window - Legnth of time to go back and look for transfers
my $netflow_window = 2; #in hours
#Polling Interval - Copy of Watchdog in minutes which seems fixed in ossim-agent
my $pi = 3;
#For plugin generation
my $plugin_id = 90012;
my $plugin_name = 'NF-Alert';
my $plugin_desc = 'Netflow Alerts';


############################################End User Config
#Command Line Switches
$Getopt::Std::STANDARD_HELP_VERSION = 1;
getopts('spVvc', \%opt);
#Using debug?
my $debug = defined($opt{'v'});
my $line_debug = defined($opt{'V'});

if ($opt{'s'}) {
	#Time to make the donuts
	make_sql();
	exit;
}

if ($opt{'p'}) {
	#No witty comment here
	make_plugin();
	exit;
}

#Grab current time
my $current_time = time();

#Grab networks in use
my $networks = `grep networks= /etc/ossim/ossim_setup.conf`;
chomp($networks);
my ($net) = (split /=/, $networks)[1];
my @netblocks = split /,/, $net;

#Create filters for nfdump
my $dst_filter = join(' or dst net ', @netblocks);
my $src_filter = join(' or src net ', @netblocks);

#Logging format for nfdump
my $nf_format = 'fmt:%ts;%te;%td;%pr;%sa;%da;%sp;%dp;%byt;%bpp;%pps;%fl;%flg';

#Debug
print "Networks Found: \n" if $debug;
print "DST: $dst_filter \nSRC: $src_filter \n" if $debug;

#Make a polling date for nfdump to check
my $nfdump_check_time = DateTime->now(time_zone=> "local")->subtract( hours => $netflow_window)->strftime("%Y/%m/%d.%H:%M:%S");
my $nfdump_check_now = DateTime->now(time_zone=> "local")->strftime("%Y/%m/%d.%H:%M:%S");

my $nf_dump_cmd_download = "/usr/bin/nfdump -R '$nfdir' -t '$nfdump_check_time-$nfdump_check_now' -L '$min_download_size' -q -N -n 100 -o '$nf_format' -s record/bytes '(dst net $dst_filter) and not (src net $src_filter) and (flags F)'";
my $nf_dump_cmd_upload = "/usr/bin/nfdump -R '$nfdir' -t '$nfdump_check_time-$nfdump_check_now' -L '$min_upload_size' -q -N -n 100 -o '$nf_format' -s record/bytes '(src net $src_filter) and not (dst net $dst_filter) and (flags F)'";

print "Download Command: '$nf_dump_cmd_download'\n" if $debug;
print "Upload Command: '$nf_dump_cmd_upload'\n" if $debug;

my $nf_dl_output = `$nf_dump_cmd_download`;
my $nf_up_output = `$nf_dump_cmd_upload`;

print "Download Output: $nf_dl_output\n---End\n" if $debug;
print "Upload Output: $nf_up_output\n--End\n" if $debug;

foreach (split(/\n/, $nf_dl_output)) {
	chomp;
	#skip if our data isn't present
	next if !/\;/;
	my @fields = parse_line_custom($_);
	#Go through and look for ends within our polling interval
	if ($fields[1] > ($current_time - ($pi * 60) - 330)) {
		print "Found Event within range,  " if $debug;
		#Lets look at the bytes...
		print "Number of bytes: $fields[8] \n" if $debug;
		#Loop looking a threshold...
		foreach my $file_size (sort keys %download_alerts) {
			#print $file_size;
			if (int $fields[8] >= int $file_size ) {
				print " Threshold exceeded. $fields[8] > $file_size. Alerting...\n" if $debug;
				my $sid = $download_alerts{$file_size}[0];
				my $output = $sid . "\;" . join("\;",@fields);
				if ($debug) {
					print "If I wasn't in debug I would send to syslog:\n$output\n";
				} else {
					send_message($output);
				}
				#Found one, we can stop now
				last;
			}
		}
				
	}
	
}


#Yes, I know it's lame to dupe the above.  But I want to do other stuff with uploads in the next version....
foreach (split(/\n/, $nf_up_output)) {
	chomp;
	#skip if our data isn't present
	next if !/\;/;
	my @fields = parse_line_custom($_);
	#Go through and look for ends within our polling interval
	if ($fields[1] > ($current_time - ($pi * 60) - 330)) {
		print "Found Event within range,  " if $debug;
		#Lets look at the bytes...
		print "Number of bytes: $fields[8] \n" if $debug;
		#Loop looking a threshold...
		foreach my $file_size (sort keys %upload_alerts) {
			#print $file_size;
			if (int $fields[8] >= int $file_size ) {
				print " Threshold exceeded. $fields[8] > $file_size. Alerting...\n" if $debug;
				my $sid = $upload_alerts{$file_size}[0];
				my $output = $sid . "\;" . join("\;",@fields);
				if ($debug) {
					print "If I wasn't in debug I would send to syslog:\n$output\n";
				} else {
					send_message($output);
				}
				#Found one, we can stop now
				last;
			}
		}
				
	}
	
}

=begin comment
#Now for some TopN checkin'
if ($debug) {
	my $nfdump_check_time = DateTime->now(time_zone=> "local")->subtract( minutes => 2*$pi)->strftime("%Y/%m/%d.%H:%M:%S");
	my $nfdump_check_now = DateTime->now(time_zone=> "local")->strftime("%Y/%m/%d.%H:%M:%S");
	$nf_dump_cmd_topN = "/usr/bin/nfdump -R '$nfdir' -t '$nfdump_check_time-$nfdump_check_now' -q -N -n 10 -o csv -s srcip -s dstip";
	print "Download Command: '$nf_dump_cmd_topN'\n" if $debug;
	#my $nf_topN_output = `$nf_dump_cmd_topN`;
	print "TopN Output:\n$nf_topN_output\n--End\n" if $debug;
	foreach (split(/\n/, $nf_topN_output)) {
		chomp;
		if (/^\d{4}-\d{2}-\d{2}/) {
			my @parse_topn = parse_line_csv($_);
			print join(';',@parse_topn) . "\n";
		}
	}
}
=cut

if ($debug) {
	my $nfdump_check_time = DateTime->now(time_zone=> "local")->subtract( minutes => 2*$pi)->strftime("%Y/%m/%d.%H:%M:%S");
	my $nfdump_check_now = DateTime->now(time_zone=> "local")->strftime("%Y/%m/%d.%H:%M:%S");
	$nf_dump_cmd_topN = "/usr/bin/nfdump -R '$nfdir' -t '$nfdump_check_time-$nfdump_check_now' -q -N -B -o '$nf_format' '(src net $src_filter) and pps>0'";
	print "Dump Command: '$nf_dump_cmd_topN'\n" if $debug;
	my $nf_topN_output = `$nf_dump_cmd_topN`;
	#print "TopN Output:\n$nf_topN_output\n--End\n" if $debug;
	my @ips;
	my %count_hash;
	foreach (split(/\n/, $nf_topN_output)) {
		chomp;
		if (/^\d{4}-\d{2}-\d{2}/) {
			my @parse_topn = parse_line_custom($_);
			#print join(';',@parse_topn) . "\n";
			push @ips, $parse_topn[4];
			#Do some checks here
		}
	}
	#Count the uniqueness for 1-Many alerts
	$count_hash{$_}++ for @ips;
	#print Dumper(%count_hash);
	print "Host Counts:\n";
	while ( my ($ip,$count) = each(%count_hash) ) {
		print "$ip - $count: ";
		if ($count > 20) {
			print "Alert";
		}
		print "\n";
	}
}



#parse_line(formats) -> threshold(fields, field, alert_hash)

#ts,te,td,pr,val,fl,flP,ipkt,ipktP,ibyt,ibytP,pps,pbs,bpp
#2014-08-04 14:06:10,2014-08-04 16:05:48,7178.434,any,192.168.100.69,4271,21.6,82698,21.9,82977188,36.2,11,92473,1003
sub parse_line_csv () {
	my $line = shift;
	print "Parsing Line: $_ \n" if $line_debug;
	my @fields = split /,/;
	#Nfdump adds spacing for some reason...remove it.
	s/^\s+|\s+$//g for(@fields);
	#Change fields to unixtime
	$fields[0] = floor(str2time($fields[0]));
	$fields[1] = floor(str2time($fields[1]));
	print "Pretty Bytes: " . scaledbytes($fields[9]) . "\n" if $line_debug;
	push @fields, scaledbytes($fields[9]);
	if ($fields[2] != 0) {
		push @fields, $fields[5] / $fields[2];
	}
	return @fields;
}

sub parse_line_custom() {
	my $line = shift;
	print "Parsing Line: $_ \n" if $line_debug;
	my @fields = split /\;/;
	#Nfdump adds spacing for some reason...remove it.
	s/^\s+|\s+$//g for(@fields);
	#Change fields to unixtime
	$fields[0] = floor(str2time($fields[0]));
	$fields[1] = floor(str2time($fields[1]));
	#Add pretty bytes
	print "Pretty Bytes: " . scaledbytes($fields[8]) . "\n" if $line_debug;
	push @fields, scaledbytes($fields[8]);
	#Add Flows/second
	my $duration = $fields[2] * 1;
	if ( $duration > 0) {
		push @fields, $fields[11] / $duration;
	} else {
		push @fields, 0;
	}
	return @fields;
}

#Straight up copy+paste: http://www.perlmonks.org/?node_id=378580
sub scaledbytes {
   (sort { length $a <=> length $b }
   map { sprintf '%.3g%s', $_[0]/1024**$_->[1], $_->[0] }
   [" bytes"=>0],[KB=>1],[MB=>2],[GB=>3],[TB=>4],[PB=>5],[EB=>6])[0]
}

sub send_message {
	my $log = shift;
	#send log message, changing IPs if needed....
	openlog($plugin_name, '', 'local6');    # don't forget this
	syslog("notice", $log);
	closelog();
}

sub make_sql () {
	my $sql_out = "INSERT INTO `plugin_sid` (`plugin_id`,`sid`,`reliability`, `priority`, `name`) VALUES ($plugin_id, %s, %s, %s, '%s');\n";
	#Print Header
	print "DELETE FROM plugin WHERE id = '$plugin_id';\n";
	print "DELETE FROM plugin_sid where plugin_id = '$plugin_id';\n";
	print "INSERT IGNORE INTO software_cpe VALUES ('cpe:/h:$plugin_name:$plugin_name:-', '$plugin_name', '1.0' , '$plugin_name $plugin_name 1.0', '$plugin_name', '$plugin_name:$plugin_id');\n";
	print "INSERT IGNORE INTO plugin (id, type, name, description,product_type,vendor) VALUES ($plugin_id, 1, '$plugin_name', '$plugin_desc',17,'AlienVault');\n";
	my @list = (values %download_alerts, values %upload_alerts);
	foreach my $event (@list) {
		printf $sql_out, @$event[0], 5, 1, @$event[1];
	}
}

sub make_plugin () {
	use File::Basename;
	use Cwd 'abs_path';
	my $script = basename($0);
	$script =~ s/\.pl//;
	my $fullpath = abs_path($0);
	print <<EOF
# Alienvault plugin
# Author: js aka PacketInspector
# Plugin $plugin_name id:$plugin_id version: 1.0
[DEFAULT]
plugin_id=$plugin_id

[config]
type=detector
enable=yes

source=log
location=/var/log/$script.log

# create log file if it does not exists,
# otherwise stop processing this plugin
create_file=false

process=$script
start=yes   ; launch plugin process when agent starts
stop=no     ; shutdown plugin process when agent stops
restart=yes  ; restart plugin process after each interval
restart_interval=180
startup=$fullpath
shutdown=


[simplematch]
event_type=event
regexp="$plugin_name:\\s+(?P<sid>[^;]+);(?P<start_time>[^;]+);(?P<end_time>[^;]+);(?P<durration>[^;]+);(?P<proto>[^;]+);(?P<src_ip>[^;]+);(?P<dst_ip>[^;]+);(?P<src_port>[^;]+);(?P<dst_port>[^;]+);(?P<bytes>[^;]+);(?P<bpp>[^;]+);(?P<pps>[^;]+);(?P<flows>[^;]+);(?P<flags>[^;]+);(?P<pbytes>[^;]+)"
plugin_sid={\$sid}
date={normalize_date(\$end_time)}
src_ip={\$src_ip}
dst_ip={\$dst_ip}
src_port={\$src_port}
dst_port={\$dst_port}
protocol={\$proto}
userdata1={\$bytes}
userdata2={\$bpp}
userdata3={\$pps}
userdata4={\$flags}
userdata5={\$pbytes}

EOF
}

sub HELP_MESSAGE { print " -s Make the SQL for plugin: $0 -s | ossim-db\n -p Make the plugin: $0 -p > /etc/ossim/agent/plugins/$plugin_name.cfg\n -c Do the Check\n -v Be Verbose\n -V show line processing\n"; }
sub VERSION_MESSAGE { print "NF-Alert to SIEM\n"; }

#/usr/bin/nfdump -R '/var/cache/nfdump/flows/live' -t '2014/07/26.15:17:00-2014/07/26.15:20:00' -o extended -s record/bytes '(dst net 192.168.0.0/16 or dst net 172.16.0.0/12 or dst net 10.0.0/8) and not (src net 192.168.0.0/16 or src net 172.16.0.0/12 or src net 10.0.0/8)' -L '+25M' -n 75
#2014-07-26 15:14:02.114   106.609 TCP        199.96.57.7:443   ->   192.168.100.75:54556 .AP.SF 184    20117   30.2 M      188    2.3 M   1499     1


