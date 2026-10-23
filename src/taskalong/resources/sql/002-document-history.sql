CREATE TABLE document_history (
    kind TEXT NOT NULL,
    identity TEXT NOT NULL,
    digest TEXT NOT NULL UNIQUE,
    schema_version TEXT NOT NULL,
    document TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY(kind, identity, digest)
);
CREATE TABLE store_migrations (
    number INTEGER PRIMARY KEY,
    operation_key TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL,
    document TEXT NOT NULL
);
CREATE TRIGGER immutable_document_history_update BEFORE UPDATE ON document_history BEGIN SELECT RAISE(ABORT,'immutable document history'); END;
CREATE TRIGGER immutable_document_history_delete BEFORE DELETE ON document_history BEGIN SELECT RAISE(ABORT,'immutable document history'); END;
CREATE TRIGGER immutable_store_migrations_update BEFORE UPDATE ON store_migrations BEGIN SELECT RAISE(ABORT,'immutable migration history'); END;
CREATE TRIGGER immutable_store_migrations_delete BEFORE DELETE ON store_migrations BEGIN SELECT RAISE(ABORT,'immutable migration history'); END;
