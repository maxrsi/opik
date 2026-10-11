--liquibase formatted sql
--changeset maxrsi:900001_create_audit_logs
--comment: Fork-only audit log of write operations and authentication events (opik-backend + opik-auth). Retention 180 days via TTL. The 9xxxxx prefix keeps it after every upstream 000xxx migration (includeAll sorts by file name).

CREATE TABLE IF NOT EXISTS ${ANALYTICS_DB_DATABASE_NAME}.audit_logs ON CLUSTER '{cluster}'
(
    id                   FixedString(36),
    event_time           DateTime64(3, 'UTC') DEFAULT now64(3),
    source               LowCardinality(String),
    workspace_id         String,
    workspace_name       String,
    actor                String,
    actor_type           LowCardinality(String),
    credential_id        String,
    action               LowCardinality(String),
    outcome              LowCardinality(String),
    http_method          LowCardinality(String),
    route                String,
    path                 String,
    status               UInt16,
    resource_type        LowCardinality(String),
    resource_id          String,
    path_params          Map(String, String),
    required_permissions Array(LowCardinality(String)),
    client_ip            String,
    user_agent           String,
    trace_id             String,
    duration_ms          UInt32,
    details              String
)
ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/${ANALYTICS_DB_DATABASE_NAME}/audit_logs', '{replica}')
PARTITION BY toYYYYMM(event_time)
ORDER BY (workspace_id, event_time, id)
TTL toDateTime(event_time) + INTERVAL 180 DAY;

--rollback DROP TABLE IF EXISTS ${ANALYTICS_DB_DATABASE_NAME}.audit_logs ON CLUSTER '{cluster}';
