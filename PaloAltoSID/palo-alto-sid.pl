#!/usr/bin/perl

use LWP::Simple;

$pa_host = '192.168.100.100';
$xml_key = '';  #Get this with: http(s):hostname/api/?type=keygen&user=username&password=password
$pa_api_url = "https://$pa_host/api/?type=config&action=get&xpath=%2Fconfig%2Fpredefined%2Fthreats%2Fvulnerability%2Fentry&key=$xml_key";
$output_file = '/tmp/paloalto.sql';  # you could rewrite this and pipe it directly to ossim-db....

open (FILE, ">$output_file") or die("Can not write to output file");

#Lets grab the sigs
my $doc = get("$pa_api_url") or die("URL can not be reached...");

#initial plugin
$pa_sql = <<END;
-- Palo Alto Firewall
-- plugin_id: 1615

DELETE FROM plugin WHERE id = "1615";
DELETE FROM plugin_sid where plugin_id = "1615";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (1615, 1, 'paloalto', 'PaloAlto Firewall');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, name, priority, reliability,subcategory_id, category_id) VALUES (1615, 1, 'PaloAlto: TRAFFIC start', 1, 5,121,3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, name, priority, reliability,subcategory_id, category_id) VALUES (1615, 2, 'PaloAlto: TRAFFIC end', 1, 5,121,3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, name, priority, reliability,subcategory_id, category_id) VALUES (1615, 3, 'PaloAlto: TRAFFIC drop', 2, 5,76,3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, name, priority, reliability,subcategory_id, category_id) VALUES (1615, 4, 'PaloAlto: TRAFFIC deny', 2, 5,76,3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, name, priority, reliability,subcategory_id, category_id) VALUES (1615, 5, 'PaloAlto: URL Blocked', 1, 2,30,3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, name, priority, reliability,subcategory_id, category_id) VALUES (1615, 6, 'PaloAlto: Vulnerability', 1, 2,11,1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, name, priority, reliability) VALUES (1615, 11, 'PaloAlto: CONFIG event', 1, 5);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, name, priority, reliability) VALUES (1615, 21, 'PaloAlto: SYSTEM general', 1, 5);

-- failsave event
INSERT IGNORE INTO plugin_sid (plugin_id, sid, name, priority, reliability) VALUES (1615, 99, 'PaloAlto: Unknown event', 1, 5);
END

$sql_statement = "INSERT IGNORE INTO plugin_sid (plugin_id, sid, name, priority, reliability,subcategory_id, category_id) VALUES (1615, %s, 'PaloAlto: %s', 1, 5,171,15);\n";

#write initial plugin
print FILE "$pa_sql\n";

#Loop through and grab IDs
while ($doc =~ /entry\ name\=\"(\d+)\".*?\<threatname\>(.*?)\<\/threatname\>/g) {
	#you might want some more checks in here
	$name = $2;
	$sid = $1;
	next if ($sid !~ /^\d+$/);
	$name =~ s/\'//g;
	printf FILE $sql_statement,$sid,$name;
}