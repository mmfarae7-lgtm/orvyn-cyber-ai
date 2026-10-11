import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
  },
});

export type ScanStatus =
  | 'pending'
  | 'running'
  | 'waiting_agent'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type Scan = {
  id: string;
  user_id: string;
  target: string;
  tool: string;
  status: ScanStatus;
  options: Record<string, unknown>;
  results: Record<string, unknown>;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  /** scan profile (quick/standard/comprehensive/custom) — added by the platform migration */
  profile?: string | null;
  target_type?: string | null;
  /** recorded authorization: NULL = legacy client, else must be confirmed === true */
  authorization?: Record<string, unknown> | null;
  progress?: { percent?: number; state?: string; updated_at?: string } | null;
  coverage?: Record<string, unknown> | null;
  agent_id?: string | null;
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
  // evidence-first fields added by the platform migration
  confidence?: string | null;
  detection_method?: string | null;
  tool?: string | null;
  tool_version?: string | null;
  detected_at?: string | null;
  asset?: string | null;
  protocol?: string | null;
  refs?: string[] | null;
};

export type ScanPhase = {
  id: string;
  scan_id: string;
  user_id: string;
  phase: number;
  key: string;
  name: string;
  status: string;
  summary: string | null;
  detail: Record<string, unknown> | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
};

export type AgentTool = {
  name: string;
  installed: boolean;
  version?: string;
  path?: string;
  executable?: boolean;
};

export type Agent = {
  id: string;
  user_id: string;
  agent_key: string;
  name: string;
  platform: string;
  os: string | null;
  architecture: string | null;
  agent_version: string | null;
  package_manager: string | null;
  status: string;
  tools: AgentTool[];
  capabilities: string[];
  current_task: string | null;
  last_seen: string | null;
  created_at: string;
};

export type RegistryTool = {
  name: string;
  display_name: string | null;
  description: string | null;
  aliases: string[] | null;
  platforms: string[] | null;
  install: Record<string, string> | null;
  capabilities: string[] | null;
  phases: string[] | null;
  risk_level: string | null;
  url: string | null;
  enabled: boolean;
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
