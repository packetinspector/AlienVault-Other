#!/usr/bin/perl
#Generic Plugin Maker
use File::Slurp;

#For plugin generation
my $plugin_id = 90016;
my $plugin_name = 'APC-UPS';
my $plugin_desc = 'APC UPS';

#Default values for rel and pri
my $default_r = 3;
my $default_p = 1;

#filename
my $file = 'apc.txt';

my @text = read_file($file);

#Feel free to change these...
my %pri_hash = ( 'Severe' => 5, 'Informational' => 1, 'Warning' => 3);



my $sql_out = "INSERT INTO `plugin_sid` (`plugin_id`,`sid`,`reliability`, `priority`, `name`) VALUES ($plugin_id, %s, $default_r, %s, '%s');\n";
#Print Header
print "DELETE FROM plugin WHERE id = '$plugin_id';\n";
print "DELETE FROM plugin_sid where plugin_id = '$plugin_id';\n";
print "INSERT IGNORE INTO software_cpe VALUES ('cpe:/h:$plugin_name:$plugin_name:-', '$plugin_name', '1.0' , '$plugin_name $plugin_name 1.0', '$plugin_name', '$plugin_name:$plugin_id');\n";
print "INSERT IGNORE INTO plugin (id, type, name, description,product_type,vendor) VALUES ($plugin_id, 1, '$plugin_name', '$plugin_desc',17,'AlienVault');\n";

my $translate_table = "[translation]\n";
foreach my $line (@text) {
	chomp($line);
	@fields = split /,/,$line;
	$message = $fields[1]; $code = $fields[2]; $pri = $fields[3];
	if (defined $pri_hash{$pri}) {
		$priority = $pri_hash{$pri};
	} else {
		$priority = $default_p;
	}
	$message =~ s/\.//g;
	$message =~ s/^\ //;
	$message = 'APC: ' . $message;
	$sid = hex($code);
	printf $sql_out, $sid, $priority, $message;
	
	#This plugin needs a translate table, going to do that in this loop
	$translate_table .= "$code=$sid\n";
}
print $translate_table;

sub make_plugin () {
	print <<EOF
# Alienvault plugin
# Author: js
# Plugin $plugin_name id:$plugin_id version: 1.0
[DEFAULT]
plugin_id=$plugin_id
[config]
type=detector
enable=yes
source=log
location=/var/log/apc.log
# create log file if it does not exists,
# otherwise stop processing this plugin
create_file=false
process=
start=yes   ; launch plugin process when agent starts
stop=no     ; shutdown plugin process when agent stops
restart=yes  ; restart plugin process after each interval
restart_interval=180
startup=
shutdown=
EOF
}
make_plugin();
