/*
# Orvyn Cyber — vulnerabilities dedupe (STEP 3+, follow-up)

ADDITIVE ONLY. This migration does not drop tables or columns. It only:

1. Removes exact duplicate findings within the same scan, where "duplicate"
   means the same (scan_id, title, effective port) triple. The physically
   earliest row is kept; later copies are deleted. Legacy rows without a
   scan_id are never touched.
2. Adds a partial unique index so the server-side findings writer can use
   ON CONFLICT to make repeat writes idempotent instead of creating a new
   copy of the same finding on every scan retry / agent result merge.

The index is partial (WHERE scan_id IS NOT NULL) so historical orphan
findings and any future non-scan findings remain unconstrained.
*/

-- ============================================================
-- 1. Collapse any existing duplicates (keep the earliest row per key)
-- ============================================================
DELETE FROM public.vulnerabilities a
USING public.vulnerabilities b
WHERE a.scan_id IS NOT NULL
  AND a.scan_id = b.scan_id
  AND a.title = b.title
  AND COALESCE(a.port, -1) = COALESCE(b.port, -1)
  AND a.ctid > b.ctid;

-- ============================================================
-- 2. Partial unique index used by the server-side findings writer
-- ============================================================
CREATE UNIQUE INDEX IF NOT EXISTS vulnerabilities_scan_dedupe_idx
  ON public.vulnerabilities (scan_id, title, COALESCE(port, -1))
  WHERE scan_id IS NOT NULL;
