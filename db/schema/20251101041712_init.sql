-- +goose Up
-- +goose StatementBegin

-- Nodes table stores both EL and CL nodes
CREATE TABLE IF NOT EXISTS "nodes" (
    "nodeid" BLOB PRIMARY KEY,
    "layer" TEXT NOT NULL,       -- 'el' or 'cl'
    "ip" BLOB,
    "ipv6" BLOB,
    "port" INTEGER,
    "seq" INTEGER,
    "fork_digest" BLOB,          -- Fork digest from 'eth' or 'eth2' field
    "first_seen" INTEGER,
    "last_seen" INTEGER,
    "last_active" INTEGER,
    "enr" BLOB,
    "has_v4" INTEGER DEFAULT 0,  -- 1 if node supports discv4 (EL only)
    "has_v5" INTEGER DEFAULT 1,  -- 1 if node supports discv5
    "success_count" INTEGER DEFAULT 0,
    "failure_count" INTEGER DEFAULT 0,
    "avg_rtt" INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS "idx_nodes_layer" ON "nodes" ("layer");
CREATE INDEX IF NOT EXISTS "idx_nodes_last_active" ON "nodes" ("last_active" DESC);
CREATE INDEX IF NOT EXISTS "idx_nodes_fork_digest" ON "nodes" ("fork_digest");
CREATE INDEX IF NOT EXISTS "idx_nodes_layer_last_active" ON "nodes" ("layer", "last_active" DESC);

-- State table stores runtime state (local ENR, etc)
CREATE TABLE IF NOT EXISTS "state" (
    "key" TEXT PRIMARY KEY,
    "value" BLOB
);

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS "nodes";
DROP TABLE IF EXISTS "state";

-- +goose StatementEnd
