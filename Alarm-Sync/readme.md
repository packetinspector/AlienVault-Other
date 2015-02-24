Alarm Sync
=============
Syncs alarms for federated servers

Installation on Federated Server
-------

* Put this script in /usr/share/alienvault/api_core/bin/alienvault/
* invoke with
```system
# alienvault-api sync_alarms
```

Notes
----
You only need to install and run this from the fedserver. 

Highly untested.  Not much error checking yet. Use with caution.

This currently uses a 4 hour window for alarms.  You can modify that easily if you need to go further back.
