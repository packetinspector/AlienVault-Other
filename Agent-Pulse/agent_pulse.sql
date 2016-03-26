DELETE FROM plugin WHERE id = "90420";
DELETE FROM plugin_sid where plugin_id = "90420";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (90420, 1, 'pulsematch', 'AlienVault PulseMatch');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, name) VALUES
(90420, 999, 'PM: Failed to Import Redis'),
(90420, 998, 'PM: Bad Input'),
(90420, 997, 'PM: Unidentifiable Input'),
(90420, 996, 'PM: Failed to Connect to Redis'),
(90420, 900, 'PM: No Match'),
(90420, 209999, 'PM: Pulse Match')
