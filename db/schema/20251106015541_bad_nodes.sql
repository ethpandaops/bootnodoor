-- +goose Up
-- +goose StatementBegin

-- Bad nodes table stores nodes that failed admission checks
-- Used to avoid repeatedly requesting ENRs from nodes that won't pass filters
CREATE TABLE IF NOT EXISTS "bad_nodes" (
    "nodeid" BLOB PRIMARY KEY,
    "layer" TEXT NOT NULL,       -- 'el' or 'cl'
    "rejected_at" INTEGER NOT NULL,  -- Unix timestamp when node was rejected
    "reason" TEXT                -- Reason for rejection (e.g., "invalid_fork_id")
);

CREATE INDEX IF NOT EXISTS "idx_bad_nodes_layer" ON "bad_nodes" ("layer");
CREATE INDEX IF NOT EXISTS "idx_bad_nodes_rejected_at" ON "bad_nodes" ("rejected_at");

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS "bad_nodes";

-- +goose StatementEnd
