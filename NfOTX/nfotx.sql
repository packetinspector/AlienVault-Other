-- NfOTX
-- plugin_id: 90011

DELETE FROM plugin WHERE id = "90011";
DELETE FROM plugin_sid where plugin_id = "90011";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (90011, 1, 'NfOTX', 'Netflow OTX Matcher');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (90011, 1, NULL, NULL, 'Netflow OTX Match',1, 3);
