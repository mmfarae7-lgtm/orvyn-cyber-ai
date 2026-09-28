#!/usr/bin/env bash
# ====================================================================
# Orion Cyber AI - Agent environment loader
# ====================================================================
# Resolves the Supabase backend the agent should poll, in this order
# (highest priority first):
#
#   1. Environment variables: ORION_SUPABASE_URL, ORION_ANON_KEY
#   2. $HOME/.orion-config.sh
#   3. <agent dir>/orion-config.sh   (created from orion-config.sh.example)
#   4. <repo root>/.env
#
# There is deliberately NO hardcoded default project. If nothing is
# configured the agent refuses to start, so it can never silently poll
# a backend that does not belong to you.
#
# Sets:
#   SUPABASE_URL, SUPABASE_ANON_KEY, AGENT_ID, POLL_INTERVAL
# Provides:
#   orion_require_config  - aborts with instructions if unconfigured
# ====================================================================

orion_env_load() {
  local agent_dir
  agent_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  # Capture values that came from the environment BEFORE any file is
  # sourced, so an explicit export always wins over a config file.
  local env_url="${ORION_SUPABASE_URL:-}"
  local env_anon="${ORION_ANON_KEY:-}"
  local env_agent="${ORION_AGENT_ID:-}"
  local env_poll="${ORION_POLL_INTERVAL:-}"
  local env_yara="${ORION_YARA_RULES:-}"

  # 2) per-user config
  if [ -f "$HOME/.orion-config.sh" ]; then
    # shellcheck disable=SC1091
    . "$HOME/.orion-config.sh"
  fi

  # 3) repo-local config
  if [ -f "$agent_dir/orion-config.sh" ]; then
    # shellcheck disable=SC1091
    . "$agent_dir/orion-config.sh"
  fi

  # 4) repo .env
  if [ -f "$agent_dir/../.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$agent_dir/../.env"
    set +a
  fi

  # 1) explicit environment variables take highest priority
  SUPABASE_URL="${env_url:-${ORION_SUPABASE_URL:-${SUPABASE_URL:-}}}"
  SUPABASE_ANON_KEY="${env_anon:-${ORION_ANON_KEY:-${SUPABASE_ANON_KEY:-}}}"
  AGENT_ID="${env_agent:-${ORION_AGENT_ID:-${AGENT_ID:-}}}"
  POLL_INTERVAL="${env_poll:-${ORION_POLL_INTERVAL:-${POLL_INTERVAL:-5}}}"
  YARA_RULES="${env_yara:-${ORION_YARA_RULES:-}}"
}

orion_require_config() {
  local missing=()
  [ -n "$SUPABASE_URL" ] || missing+=("ORION_SUPABASE_URL")
  [ -n "$SUPABASE_ANON_KEY" ] || missing+=("ORION_ANON_KEY")

  if [ ${#missing[@]} -gt 0 ]; then
    {
      echo "ERROR: Orion backend is not configured."
      echo ""
      echo "Missing: ${missing[*]}"
      echo ""
      echo "Fix it with either:"
      echo ""
      echo "  1) Create your config file:"
      echo "       cp termux-agent/orion-config.sh.example termux-agent/orion-config.sh"
      echo "     then set:"
      echo "       ORION_SUPABASE_URL=\"https://<your-project-ref>.supabase.co\""
      echo "       ORION_ANON_KEY=\"<your-anon-key>\""
      echo ""
      echo "  2) Or export the variables before running the agent:"
      echo "       export ORION_SUPABASE_URL=\"https://<your-project-ref>.supabase.co\""
      echo "       export ORION_ANON_KEY=\"<your-anon-key>\""
      echo ""
      echo "Find both values in: Supabase Dashboard -> Project Settings -> API"
    } >&2
    exit 1
  fi
}
