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
