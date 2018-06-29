-- REMOVE EMPTY AppIDs from handles
-- From r28 we should add AppId to the identifier handle only
-- SELECT COUNT(*) FROM dbs_pids.handles where `idx` = 103 and `data` = '';
--
DELETE FROM dbs_pids.handles where `idx` = 103 and `data` = '';