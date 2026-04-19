-- Reclassify rows that were backfilled from the legacy FindingScope enum.
--
-- 20260419120000_unified_findings mapped every `scope IN (people, people_tasks,
-- people_devices, people_chart)` row onto `area = 'people'` so they stayed
-- queryable. In hindsight that misrepresents them: a finding that used to have
-- scope `people_chart` is about the org chart, not the people directory. Move
-- those backfilled rows to `area = 'other'` so UI filters can treat them as
-- unclassified/historical.
--
-- Cutoff is the unified_findings migration timestamp. Before that point the
-- `area` column didn't exist, so any Finding with `area = 'people'` and
-- `createdAt < 2026-04-19 12:00:00 UTC` can only have been populated by the
-- backfill statement — it's safe to reclassify. Anything created after the
-- cutoff is a genuine `area = 'people'` finding and is left alone.
UPDATE "Finding"
SET "area" = 'other'
WHERE "area" = 'people'
  AND "createdAt" < TIMESTAMP '2026-04-19 12:00:00';
