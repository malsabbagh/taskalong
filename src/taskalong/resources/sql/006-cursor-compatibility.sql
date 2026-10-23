-- Compatibility fence for Cursor fixture documents and observed-session history.
-- Existing immutable document and attempt storage suffices; no tables are added.
-- Only explicit quiescent maintenance may commit this numbered fence.
SELECT 1;
