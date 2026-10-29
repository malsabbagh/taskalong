-- A compatibility fence and append-only controller exposure history.
-- Local cessation never settles remotely accepted inference.
CREATE TABLE muse_exposure_events (
    sequence INTEGER PRIMARY KEY,
    attempt_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    phase TEXT NOT NULL CHECK (phase IN ('reserved','release_attempted','not_sent','local_stopped','local_unknown')),
    document TEXT NOT NULL,
    UNIQUE (attempt_id, phase)
);
CREATE TRIGGER muse_exposure_no_update BEFORE UPDATE ON muse_exposure_events
BEGIN SELECT RAISE(ABORT, 'immutable Muse exposure history'); END;
CREATE TRIGGER muse_exposure_no_delete BEFORE DELETE ON muse_exposure_events
BEGIN SELECT RAISE(ABORT, 'immutable Muse exposure history'); END;
