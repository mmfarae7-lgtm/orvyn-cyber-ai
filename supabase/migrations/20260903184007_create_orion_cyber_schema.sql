/*
# Orion Cyber AI - Database Schema

## Overview
Creates the full database schema for the Orion Cyber AI security scanning platform.
This is a multi-user application with authentication, scan management, vulnerability tracking,
AI chat assistant, and an interactive lab.

## New Tables

### profiles
- Extends auth.users with display name and avatar URL
- `id` (uuid, PK, references auth.users)
- `display_name` (text)
- `avatar_url` (text, nullable)
- `created_at` (timestamptz)

### scans
- Stores scan configurations and results
- `id` (uuid, PK)
- `user_id` (uuid, references auth.users)
- `target` (text) - the target URL or IP to scan
- `tool` (text) - which scanning tool was used
- `status` (text) - pending, running, completed, failed
- `options` (jsonb) - scan configuration options
- `results` (jsonb) - raw scan results
- `started_at` (timestamptz)
- `completed_at` (timestamptz)
- `created_at` (timestamptz)

### vulnerabilities
- Individual findings from scans
- `id` (uuid, PK)
- `scan_id` (uuid, references scans)
- `user_id` (uuid, references auth.users)
- `title` (text) - vulnerability title
- `severity` (text) - critical, high, medium, low, info
- `description` (text)
- `evidence` (text) - proof/data from the scan
- `remediation` (text) - how to fix it
- `cve` (text, nullable) - CVE ID if applicable
- `port` (integer, nullable)
- `service` (text, nullable)
- `created_at` (timestamptz)

### chat_messages
- AI security assistant conversation history
- `id` (uuid, PK)
- `user_id` (uuid, references auth.users)
- `role` (text) - user or assistant
- `content` (text)
- `created_at` (timestamptz)

### lab_sessions
- Interactive tool testing sessions
- `id` (uuid, PK)
- `user_id` (uuid, references auth.users)
- `tool` (text) - which tool is being used
- `command` (text) - the command/input
- `output` (jsonb) - results
- `status` (text) - running, completed, failed
- `created_at` (timestamptz)

## Security
- RLS enabled on all tables
- All tables are owner-scoped (user_id = auth.uid())
- Profiles table allows users to read/update their own profile
*/

-- Profiles table
CREATE TABLE IF NOT EXISTS profiles (
  id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  display_name text NOT NULL DEFAULT '',
  avatar_url text,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_profile" ON profiles;
CREATE POLICY "select_own_profile" ON profiles FOR SELECT
  TO authenticated USING (auth.uid() = id);

DROP POLICY IF EXISTS "insert_own_profile" ON profiles;
CREATE POLICY "insert_own_profile" ON profiles FOR INSERT
  TO authenticated WITH CHECK (auth.uid() = id);

DROP POLICY IF EXISTS "update_own_profile" ON profiles;
CREATE POLICY "update_own_profile" ON profiles FOR UPDATE
  TO authenticated USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  target text NOT NULL,
  tool text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  options jsonb DEFAULT '{}'::jsonb,
  results jsonb DEFAULT '{}'::jsonb,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_scans" ON scans;
CREATE POLICY "select_own_scans" ON scans FOR SELECT
  TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "insert_own_scans" ON scans;
CREATE POLICY "insert_own_scans" ON scans FOR INSERT
  TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "update_own_scans" ON scans;
CREATE POLICY "update_own_scans" ON scans FOR UPDATE
  TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "delete_own_scans" ON scans;
CREATE POLICY "delete_own_scans" ON scans FOR DELETE
  TO authenticated USING (auth.uid() = user_id);

-- Vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid REFERENCES scans(id) ON DELETE CASCADE,
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  title text NOT NULL,
  severity text NOT NULL DEFAULT 'info',
  description text NOT NULL DEFAULT '',
  evidence text NOT NULL DEFAULT '',
  remediation text NOT NULL DEFAULT '',
  cve text,
  port integer,
  service text,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_vulns" ON vulnerabilities;
CREATE POLICY "select_own_vulns" ON vulnerabilities FOR SELECT
  TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "insert_own_vulns" ON vulnerabilities;
CREATE POLICY "insert_own_vulns" ON vulnerabilities FOR INSERT
  TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "update_own_vulns" ON vulnerabilities;
CREATE POLICY "update_own_vns" ON vulnerabilities FOR UPDATE
  TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "delete_own_vulns" ON vulnerabilities;
CREATE POLICY "delete_own_vulns" ON vulnerabilities FOR DELETE
  TO authenticated USING (auth.uid() = user_id);

-- Chat messages table
CREATE TABLE IF NOT EXISTS chat_messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  role text NOT NULL,
  content text NOT NULL,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE chat_messages ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_chat" ON chat_messages;
CREATE POLICY "select_own_chat" ON chat_messages FOR SELECT
  TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "insert_own_chat" ON chat_messages;
CREATE POLICY "insert_own_chat" ON chat_messages FOR INSERT
  TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "delete_own_chat" ON chat_messages;
CREATE POLICY "delete_own_chat" ON chat_messages FOR DELETE
  TO authenticated USING (auth.uid() = user_id);

-- Lab sessions table
CREATE TABLE IF NOT EXISTS lab_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL DEFAULT auth.uid() REFERENCES auth.users(id) ON DELETE CASCADE,
  tool text NOT NULL,
  command text NOT NULL DEFAULT '',
  output jsonb DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'completed',
  created_at timestamptz DEFAULT now()
);

ALTER TABLE lab_sessions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "select_own_lab" ON lab_sessions;
CREATE POLICY "select_own_lab" ON lab_sessions FOR SELECT
  TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "insert_own_lab" ON lab_sessions;
CREATE POLICY "insert_own_lab" ON lab_sessions FOR INSERT
  TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "delete_own_lab" ON lab_sessions;
CREATE POLICY "delete_own_lab" ON lab_sessions FOR DELETE
  TO authenticated USING (auth.uid() = user_id);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_user_id ON vulnerabilities(user_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_scan_id ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_chat_messages_user_id ON chat_messages(user_id);
CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at ON chat_messages(created_at);
CREATE INDEX IF NOT EXISTS idx_lab_sessions_user_id ON lab_sessions(user_id);

-- Trigger to auto-create profile on signup
CREATE OR REPLACE FUNCTION handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO profiles (id, display_name)
  VALUES (NEW.id, COALESCE(NEW.raw_user_meta_data->>'display_name', ''));
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION handle_new_user();