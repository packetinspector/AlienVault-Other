#!/usr/bin/perl
use DBI();

#Ripped from ossim-db
my $user = `grep ^user= /etc/ossim/ossim_setup.conf | cut -f 2 -d "=" | sed '/^\$/d'`;
my $pass = `grep ^pass= /etc/ossim/ossim_setup.conf | cut -f 2 -d "=" | sed '/^\$/d'`;
#Sed should do this but just in case...
chomp($user);chomp($pass);
#Init DB. We'll use this everytime
my $dbh = DBI->connect("DBI:mysql:database=alienvault;host=127.0.0.1",$user, $pass, {'RaiseError' => 1});

#Orphan Query
$orphans = 'select hex(h.id) as host_id, h.hostname, hex(h.ctx) as host_context, e.name from  host h, acl_entities e where h.ctx = e.id and h.id NOT IN (select host_id from host_sensor_reference)';
#Run
my $sth = $dbh->prepare($orphans);
$sth->execute();
while (my $res = $sth->fetchrow_hashref()) {
	print "Found Orphan: $res->{'hostname'} ($res->{'host_id'}) it belongs to context $res->{'name'} ($res->{'host_context'})\n";
	print "Finding Sensor....";
	$find_sensor = "select hex(ac.entity_id) as entity_id ,hex(ac.sensor_id) as sensor_id, s.name as name from acl_sensors ac, sensor s WHERE ac.sensor_id = s.id and entity_id = unhex('%s')";
	$find_sensor_query = sprintf($find_sensor, $res->{'host_context'});
	my $sq = $dbh->prepare($find_sensor_query);
	$sq->execute();
	$numRows = $sq->rows;
	if ($numRows > 0) {
		my $sensor = $sq->fetchrow_hashref();
		print "Found $numRows Sensor: $sensor->{'name'} ( $sensor->{'sensor_id'} ) \n";
		print "Inserting into Sensor Reference....";
		$i = $dbh->do("INSERT INTO host_sensor_reference (host_id,sensor_id) VALUES (unhex(?), unhex(?))", undef, $res->{'host_id'}, $sensor->{'sensor_id'});
		if (!$i or $i eq '0E0') {
			print "Failed or No Insert: " . $dbh->errstr . "\n";
		} else {
			print "Success!!\n";
		}
	} else {
		print "No Sensor Found!\n";
	}
	
}
