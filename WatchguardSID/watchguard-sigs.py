#!/usr/bin/python

import requests
import sys
import MySQLdb

#You modify this stuff
wg_device = '<IP.OF.Watchguard>'
login_form = {
    "username": "<device_monitor_user>",
    "password": "<device_monitor_pass>",
    "domain": "Firebox-DB"
}

#No need to modify this stuff
sig_link = 'https://' + wg_device + ':8080/security/ips_signatures'
login_url = 'https://' + wg_device + ':8080/auth/login'

sql_insert = 'REPLACE INTO plugin_sid (plugin_id, sid, priority, reliability, category_id, subcategory_id, name) VALUES'
sql_value = "(1691, %s, %s, 2, 15, 171, '%s')"

# "sid": "7FDCC2331BEFD79F41A7C4C96B68079A0000000D",
#    "privilege": 2
#{u'Category': 16, u'Impact': u'Remote code execution', u'Name': u'EXPLOIT GNU Radius SQL Accounting Format String Vulnerability (CVE-2006-4181)', u'Release_Date': u'2014-12-15 08:20:53', u'Recommend': u"Update vendor's patch.", u'Default_Action': 80000011, u'Severity': 4, u'Desc': u'There exists a format string vulnerability in the GNU Radius suite. The flaw may be exploited by sending a malicious request message to the Radius daemon.'}

debug = False
requests.packages.urllib3.disable_warnings()

#Login to WG
wg = requests.session()
if debug: print "Getting Session ID"
r = wg.post(login_url, verify=False, data=login_form)
if not r.ok:
    print "Failed to Connect."
    sys.exit(0)
#Get the JSON
if debug: print "Downloading Sigs..."
r = wg.get(sig_link, verify=False)
if not r.ok:
    print "Failed to Download Sigs."
    sys.exit(0)

output = r.json()
if debug: print "Signature Version: " + output['signature_version_text']
sigs = output['sig_ips_list']
#
i = 0
last = len(sigs)

print sql_insert

for sigid, signature in sigs.iteritems():
    i = i + 1
    if debug: print signature
    #if debug: print sigid, signature['Name'], signature['Severity']
    name = 'Watchguard: ' + str(MySQLdb.escape_string(signature['Name']))
    print sql_value % (sigid, signature['Severity'], name),
    if i == last:
        print ";"
    else:
        print ","
    if debug:
        if i > 15:
            break
