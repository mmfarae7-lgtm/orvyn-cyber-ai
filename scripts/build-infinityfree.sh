#!/usr/bin/env bash
# ====================================================================
# Orvyn Cyber AI - build the static bundle for InfinityFree
# ====================================================================
# InfinityFree serves PHP 8.4 + static files only. It cannot run the
# Supabase backend, so what gets deployed here is the built frontend
# plus a small PHP status page. The browser talks to Supabase directly.
#
# Usage:
#   ./scripts/build-infinityfree.sh
#   # then upload the contents of deploy/infinityfree/htdocs/ via FTP
#   # or the InfinityFree control panel File Manager
# ====================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/deploy/infinityfree/htdocs"

cd "$ROOT"

if [ ! -f .env ] && [ ! -f .env.local ]; then
  echo "ERROR: no .env found."
  echo "Create one from .env.example and set VITE_SUPABASE_URL + VITE_SUPABASE_ANON_KEY"
  echo "so the bundle points at your Supabase project."
  exit 1
fi

echo "==> Building frontend"
npm run build

# Read the project URL from .env so status.php needs no manual editing.
set -a
# shellcheck disable=SC1091
. ./.env
set +a

if [ -z "${VITE_SUPABASE_URL:-}" ]; then
  echo "ERROR: VITE_SUPABASE_URL is not set in .env"
  exit 1
fi

echo "==> Assembling $OUT"
rm -rf "$OUT"
mkdir -p "$OUT"

cp -r dist/. "$OUT/"

# The SPA owns index.html at the web root, so the status page is named
# status.php. Naming it index.php would make Apache serve the status page
# instead of the app.
sed "s#YOUR-SUPABASE-URL#${VITE_SUPABASE_URL}#" \
  deploy/infinityfree/index.php > "$OUT/status.php"

if grep -q 'YOUR-SUPABASE-URL' "$OUT/status.php"; then
  echo "ERROR: project URL was not substituted into status.php"
  exit 1
fi

# vite.config.ts already sets base: './', so asset URLs are relative and
# work from any subdirectory (e.g. the /~user/oryvn free subdomain path).
# No path rewriting is needed.

if [ -f public/orvyn-logo.png ]; then
  cp public/orvyn-logo.png "$OUT/" 2>/dev/null || true
fi

echo ""
echo "Done. Upload the contents of:"
echo "  $OUT"
echo "to your InfinityFree account's web root (htdocs)."
echo ""
echo "Backend health will be reported at /status.php"
