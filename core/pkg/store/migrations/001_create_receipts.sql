CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL,
    execution_intent_id TEXT,
    status TEXT NOT NULL,
    result BYTEA,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    executor_id TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    lamport_clock BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_receipts_decision_id ON receipts (decision_id);
CREATE INDEX IF NOT EXISTS idx_receipts_executor_clock ON receipts (executor_id, lamport_clock DESC);
