import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
  },
});

export type Scan = {
  id: string;
  user_id: string;
  target: string;
  tool: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  options: Record<string, unknown>;
  results: Record<string, unknown>;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
};

export type Vulnerability = {
  id: string;
  scan_id: string | null;
  user_id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  evidence: string;
  remediation: string;
  cve: string | null;
  port: number | null;
  service: string | null;
  created_at: string;
};

export type ChatMessage = {
  id: string;
  user_id: string;
  role: 'user' | 'assistant';
  content: string;
  created_at: string;
};

export type LabSession = {
  id: string;
  user_id: string;
  tool: string;
  command: string;
  output: Record<string, unknown>;
  status: 'running' | 'completed' | 'failed';
  created_at: string;
};

export type Profile = {
  id: string;
  display_name: string;
  avatar_url: string | null;
  created_at: string;
};
