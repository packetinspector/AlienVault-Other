##Download Signature IDs from a Watchguard UTM Device

- Author: PacketInspector ([@pkt_inspector](https://twitter.com/pkt_inspector))

####First Steps

- Update IP Address of appliance in the script
- Create a user with device monitor priv
- Put user creds in script

####Run Script
```
./watchguard-sigs.py > /tmp/wg-sids.sql
cat /tmp/wq-sids.sql | ossim-db
```
or if you're brave
```
./watchguard-sigs.py | ossim-db
```

####Notes
- Update SIDs requires ossim-server restart
- Flip the debug var if you want to see more output

