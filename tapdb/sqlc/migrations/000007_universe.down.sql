DROP TABLE IF EXISTS universe_leaves;
DROP TABLE IF EXISTS universe_roots;
DROP TABLE IF EXISTS universe_servers;
DROP TABLE IF EXISTS federation_global_sync_config;
DROP TABLE IF EXISTS federation_uni_sync_config;
DROP INDEX IF EXISTS universe_servers_host;
DROP TABLE IF EXISTS universe_events;
DROP INDEX IF EXISTS universe_events_event_time_idx;
DROP INDEX IF EXISTS universe_events_type_idx;
DROP INDEX IF EXISTS universe_roots_asset_id_idx;
DROP INDEX IF EXISTS universe_roots_group_key_idx;
DROP INDEX IF EXISTS universe_leaves_key_idx;
DROP INDEX IF EXISTS universe_leaves_namespace;