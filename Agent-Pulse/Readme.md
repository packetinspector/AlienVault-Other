##Agent Pulse

- Author: PacketInspector ([@pkt_inspector](https://twitter.com/pkt_inspector))
- This is a POC that works


####Plugin Install:
```
Customer450:~/github/AlienVault-Other/Agent-Pulse# cp agent_pulse.cfg /etc/ossim/agent/plugins/
Customer450:~/github/AlienVault-Other/Agent-Pulse# cp agent_pulse_function.cfg /etc/ossim/agent/plugins/custom_functions/
Customer450:~/github/AlienVault-Other/Agent-Pulse# cat agent_pulse.sql | ossim-db
Customer450:~/github/AlienVault-Other/Agent-Pulse# dpkg-reconfigure alienvault-cpe
Loading cpe data in DB...
Updating software_cpe plugins...
Customer450:~/github/AlienVault-Other/Agent-Pulse# /etc/init.d/ossim-server restart
Restarting ossim-server
. ok
Customer450:~/github/AlienVault-Other/Agent-Pulse#
(choose asset and enable plugin)
```

####What is this?
- This plugin will take a value and check its existence in the Pulse database
- If it is found it will return a special SID
- No idea how this scales but I have tested it at 100EPS
- With the limitations of custom plugin functions and speed you should overlay this on another datasource
- The sample plugin has a basic regex as an example
- This plugin will not currently tell you which pulse is matched, just that the log entry is a match
- It would be possible to return the pulse id, but you'd need to run two functions

####Why this method?

Matching by SID is fast.  I could output the pulse_id in a userdata field, but then you'd need a correlation rule or similar to find these events. 

####Sample Use Cases
- Run Filehashes from other solutions(e.g. Cylance) through for double confirmation
- Run proxy logs to match hostnames
- Run access logs to match bad actors
- Run endpoint scan logs through
