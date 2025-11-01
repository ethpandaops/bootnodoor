-- +goose Up
-- +goose StatementBegin

-- Nodes table stores discovered bootnode peers
CREATE TABLE IF NOT EXISTS "nodes" (
    "nodeid" BLOB PRIMARY KEY,
    "ip" BLOB,
    "ipv6" BLOB,
    "port" INTEGER,
    "seq" INTEGER,
    "fork_digest" BLOB,
    "first_seen" INTEGER,
    "last_seen" INTEGER,
    "last_active" INTEGER,
    "enr" BLOB,
    "success_count" INTEGER DEFAULT 0,
    "failure_count" INTEGER DEFAULT 0,
    "avg_rtt" INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS "idx_nodes_last_active" ON "nodes" ("last_active" DESC);
CREATE INDEX IF NOT EXISTS "idx_nodes_fork_digest" ON "nodes" ("fork_digest");

-- State table stores runtime state (local ENR, etc)
CREATE TABLE IF NOT EXISTS "state" (
    "key" TEXT PRIMARY KEY,
    "value" BLOB
);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS "nodes";
DROP TABLE IF EXISTS "bad_nodes";
DROP TABLE IF EXISTS "state";

-- +goose StatementEnd
