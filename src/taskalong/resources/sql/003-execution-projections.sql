CREATE TABLE execution_projections (
    binding_digest TEXT PRIMARY KEY,
    document TEXT NOT NULL
);
CREATE TRIGGER immutable_execution_projections_update BEFORE UPDATE ON execution_projections BEGIN SELECT RAISE(ABORT,'immutable execution projection'); END;
CREATE TRIGGER immutable_execution_projections_delete BEFORE DELETE ON execution_projections BEGIN SELECT RAISE(ABORT,'immutable execution projection'); END;
