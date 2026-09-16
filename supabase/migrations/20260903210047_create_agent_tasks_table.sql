/*
# Agent task queue for Termux/Kali execution backend

## Tables
- agent_tasks: queue of scan tasks to be picked up by the Termux/Kali agent
*/

CREATE TABLE IF NOT EXISTS agent_tasks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  scan_id uuid REFERENCES scans(id) ON DELETE CASCADE,
  tool text NOT NULL,
  target text NOT NULL,
  options jsonb DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
  output jsonb DEFAULT '{}'::jsonb,
  raw_output text,
  error text,
  assigned_to text,
  created_at timestamptz DEFAULT now(),
  started_at timestamptz,
  completed_at timestamptz
);

ALTER TABLE agent_tasks ENABLE ROW LEVEL SECURITY;

CREATE POLICY "select_own_tasks" ON agent_tasks FOR SELECT
  TO authenticated USING (auth.uid() = user_id);
CREATE POLICY "insert_own_tasks" ON agent_tasks FOR INSERT
  TO authenticated WITH CHECK (auth.uid() = user_id);
CREATE POLICY "update_own_tasks" ON agent_tasks FOR UPDATE
  TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
CREATE POLICY "delete_own_tasks" ON agent_tasks FOR DELETE
  TO authenticated USING (auth.uid() = user_id);

CREATE INDEX idx_agent_tasks_status ON agent_tasks(status);
CREATE INDEX idx_agent_tasks_user ON agent_tasks(user_id);