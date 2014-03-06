#!/urs/bin/perl use DBI;
$dbh = DBI->connect('DBI:mysql:sfsnort', 'root', 'admin') || die "Could not connect to database: $DBI::errstr";

$query = "select gid,sid,msg FROM rule_header ";
$insert = "INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name) VALUES (%u,%u, NULL, NULL, %s);\n";

$results = $dbh->selectall_arrayref($query,{ Slice => {} });
foreach my $sig (@$results) {
#print "Signature: $sig->{gid} - $sig->{sid}\n";
$dsid = $sig->{gid} + 1000;
$sid = $sig->{sid};
($name) = $sig->{msg} =~ /"([^"]*)"/;
$name = $dbh->quote("Sourcefire: " . $name);
#print "$dsid - $sid - $name \n";
#now make insert
printf $insert, $dsid, $sid, $name;
}
