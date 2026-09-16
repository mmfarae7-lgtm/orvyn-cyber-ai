/*
# Fix typo in vulnerabilities update policy name

## Changes
- Drops the incorrectly named policy "update_own_vns"
- Recreates it with the correct name "update_own_vulns"
*/

DROP POLICY IF EXISTS "update_own_vns" ON vulnerabilities;
DROP POLICY IF EXISTS "update_own_vulns" ON vulnerabilities;
CREATE POLICY "update_own_vulns" ON vulnerabilities FOR UPDATE
  TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);