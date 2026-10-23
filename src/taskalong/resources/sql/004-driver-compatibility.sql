-- Compatibility-only migration. Existing immutable history/projection tables
-- already store the new versioned records. No row or schema rewrite is needed.
-- The maintenance transaction records SQL004 and advances both format markers
-- only after complete backup/restore and quiescence checks. Pre-M5 clients
-- reject format4 before opening executable 2.3 state.
SELECT 1;
