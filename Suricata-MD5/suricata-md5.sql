-- Suricata-MD5
-- plugin_id: 90010

DELETE FROM plugin WHERE id = "90010";
DELETE FROM plugin_sid where plugin_id = "90010";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (90010, 1, 'Suricata-MD5', 'Suricata File Engine');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (90010, 1, NULL, NULL, 'Windows EXE Downloaded',1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, name, priority, reliability) VALUES (90010, 2, NULL, NULL, 'PDF File Download' ,1, 3);