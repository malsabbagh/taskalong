-- Compatibility-only fence for explicit 2.4 Ollama fixture execution records.
-- Existing immutable history tables suffice. Complete backup/restore and
-- quiescence precede the numbered receipt and both format-marker advances.
-- Format-4 clients reject before journal mutation or executable state access.
SELECT 1;
