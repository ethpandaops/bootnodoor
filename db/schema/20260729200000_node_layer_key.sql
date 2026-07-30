-- +goose Up
-- +goose StatementBegin

-- Reads filter on (nodeid, layer), so keying on nodeid alone let a dual-layer
-- peer's second write replace its first. SQLite cannot alter a primary key,
-- hence the rebuild. Rows already collapsed are carried over as-is; the lost
-- layer returns only on rediscovery.

CREATE TABLE "nodes_new" (
    "nodeid" BLOB NOT NULL,
    "layer" TEXT NOT NULL,
    "ip" BLOB,
    "ipv6" BLOB,
    "port" INTEGER,
    "seq" INTEGER,
    "fork_digest" BLOB,
    "first_seen" INTEGER,
    "last_seen" INTEGER,
    "last_active" INTEGER,
    "enr" BLOB,
    "has_v4" INTEGER DEFAULT 0,
    "has_v5" INTEGER DEFAULT 1,
    "success_count" INTEGER DEFAULT 0,
    "failure_count" INTEGER DEFAULT 0,
    "avg_rtt" INTEGER DEFAULT 0,
    PRIMARY KEY ("nodeid", "layer")
);

INSERT INTO "nodes_new" SELECT
    nodeid, layer, ip, ipv6, port, seq, fork_digest, first_seen, last_seen,
    last_active, enr, has_v4, has_v5, success_count, failure_count, avg_rtt
FROM "nodes";

DROP TABLE "nodes";
ALTER TABLE "nodes_new" RENAME TO "nodes";

CREATE INDEX IF NOT EXISTS "idx_nodes_layer" ON "nodes" ("layer");
CREATE INDEX IF NOT EXISTS "idx_nodes_last_active" ON "nodes" ("last_active" DESC);
CREATE INDEX IF NOT EXISTS "idx_nodes_fork_digest" ON "nodes" ("fork_digest");
CREATE INDEX IF NOT EXISTS "idx_nodes_layer_last_active" ON "nodes" ("layer", "last_active" DESC);

CREATE TABLE "bad_nodes_new" (
    "nodeid" BLOB NOT NULL,
    "layer" TEXT NOT NULL,
    "rejected_at" INTEGER NOT NULL,
    "reason" TEXT,
    PRIMARY KEY ("nodeid", "layer")
);

INSERT INTO "bad_nodes_new" SELECT nodeid, layer, rejected_at, reason FROM "bad_nodes";

DROP TABLE "bad_nodes";
ALTER TABLE "bad_nodes_new" RENAME TO "bad_nodes";

CREATE INDEX IF NOT EXISTS "idx_bad_nodes_layer" ON "bad_nodes" ("layer");
CREATE INDEX IF NOT EXISTS "idx_bad_nodes_rejected_at" ON "bad_nodes" ("rejected_at");

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin

-- Lossy by necessity: two rows cannot both fit a nodeid primary key. Keeping
-- the EL row makes the collapse deterministic rather than insertion-ordered.

CREATE TABLE "nodes_old" (
    "nodeid" BLOB PRIMARY KEY,
    "layer" TEXT NOT NULL,
    "ip" BLOB,
    "ipv6" BLOB,
    "port" INTEGER,
    "seq" INTEGER,
    "fork_digest" BLOB,
    "first_seen" INTEGER,
    "last_seen" INTEGER,
    "last_active" INTEGER,
    "enr" BLOB,
    "has_v4" INTEGER DEFAULT 0,
    "has_v5" INTEGER DEFAULT 1,
    "success_count" INTEGER DEFAULT 0,
    "failure_count" INTEGER DEFAULT 0,
    "avg_rtt" INTEGER DEFAULT 0
);

INSERT INTO "nodes_old" SELECT
    nodeid, layer, ip, ipv6, port, seq, fork_digest, first_seen, last_seen,
    last_active, enr, has_v4, has_v5, success_count, failure_count, avg_rtt
FROM "nodes"
WHERE layer = 'el'
   OR nodeid NOT IN (SELECT nodeid FROM "nodes" WHERE layer = 'el');

DROP TABLE "nodes";
ALTER TABLE "nodes_old" RENAME TO "nodes";

CREATE INDEX IF NOT EXISTS "idx_nodes_layer" ON "nodes" ("layer");
CREATE INDEX IF NOT EXISTS "idx_nodes_last_active" ON "nodes" ("last_active" DESC);
CREATE INDEX IF NOT EXISTS "idx_nodes_fork_digest" ON "nodes" ("fork_digest");
CREATE INDEX IF NOT EXISTS "idx_nodes_layer_last_active" ON "nodes" ("layer", "last_active" DESC);

CREATE TABLE "bad_nodes_old" (
    "nodeid" BLOB PRIMARY KEY,
    "layer" TEXT NOT NULL,
    "rejected_at" INTEGER NOT NULL,
    "reason" TEXT
);

INSERT INTO "bad_nodes_old" SELECT nodeid, layer, rejected_at, reason
FROM "bad_nodes"
WHERE layer = 'el'
   OR nodeid NOT IN (SELECT nodeid FROM "bad_nodes" WHERE layer = 'el');

DROP TABLE "bad_nodes";
ALTER TABLE "bad_nodes_old" RENAME TO "bad_nodes";

CREATE INDEX IF NOT EXISTS "idx_bad_nodes_layer" ON "bad_nodes" ("layer");
CREATE INDEX IF NOT EXISTS "idx_bad_nodes_rejected_at" ON "bad_nodes" ("rejected_at");

-- +goose StatementEnd
