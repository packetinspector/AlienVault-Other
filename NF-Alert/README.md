Netflow Alerts
===========================================

Takes Netflow data and alerts on conditions.  Currently it alerts on large downloads or uploads.

-------------------

Installation
--------

The SQL and Plugin file are all integrated into the script.

- Download script from here
- Also download rsyslog filter

Transcript of installation:

```
alienvault:/usr/local/bin# ./nf-alert.pl --help
NF-Alert to SIEM
 -s Make the SQL for plugin: ./nf-alert.pl -s | ossim-db
 -p Make the plugin: ./nf-alert.pl -p > /etc/ossim/agent/plugins/NF-Alert.cfg
 -c Do the Check
 -v Be Verbose
alienvault:/usr/local/bin# ./nf-alert.pl -p > /etc/ossim/agent/plugins/NF-Alert.cfg
alienvault:/usr/local/bin# ./nf-alert.pl -s | ossim-db
alienvault:/usr/local/bin# /etc/init.d/ossim-server restart
Restarting ossim-server
OSSIM-Message: Entering daemon mode...
.
alienvault:/usr/local/bin# cp nf-alert.conf /etc/rsyslog.d/
alienvault:/usr/local/bin# /etc/init.d/rsyslog restart
Stopping enhanced syslogd: rsyslogd.
Starting enhanced syslogd: rsyslogd.
alienvault:/usr/local/bin#
```

- Then enable the plug-in as normal.
- You can run with the -v switch to see it in action, it will not make an event when run this way

Use Cases
-----------
- Correlate the events of this plugin with another like Snort or Proxy
- Use your own thresholds in a correlation rule e.g. USERDATA1 > 500000000
- Use policy to create a group of hosts you would not expect to upload or download excessively


Userdata Fields
----------

Field | Data
----- | ------
userdata1 | bytes
userdata2 | bpp
userdata3 | pps
userdata4 | flags

Other Notes
-----------
The threhsolds for the events are configurable.  You'll see the values and hashes at the top of the script.  If you modify them, just re-install the plugin.

Future Versions
-----------
I believe there is more statistical information we can derive from Netflow.  Up/Down was simple, more rules to follow.



