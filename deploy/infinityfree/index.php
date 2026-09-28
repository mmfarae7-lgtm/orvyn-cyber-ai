<?php
/**
 * Orvyn Cyber AI - status page for InfinityFree.
 *
 * InfinityFree runs PHP 8.4 + MySQL on shared hosting. It cannot host the
 * Supabase backend (Postgres + GoTrue + PostgREST + Deno edge functions),
 * so this host serves the static frontend only. The app talks directly to
 * Supabase from the browser, which means no server-side proxy is needed.
 *
 * Deploy: upload the contents of the build output here.
 *   ./scripts/build-infinityfree.sh
 */

declare(strict_types=1);

// Where the live Supabase project lives, so this page can report health.
const SUPABASE_URL = 'https://YOUR-PROJECT-REF.supabase.co';

/**
 * Check whether the Supabase backend is reachable.
 *
 * Only the public auth health endpoint is contacted, with no credentials.
 * Supabase answers 401 to an unkeyed probe, which still proves GoTrue is
 * live, so both 2xx and 401 count as reachable. No user data is sent.
 *
 * @return string|null 'ok', 'http-<code>', or null when unreachable
 */
function supabaseReachable(string $url, int $timeoutSeconds = 5): ?string
{
    $context = stream_context_create([
        'http' => [
            'method'        => 'GET',
            'timeout'       => $timeoutSeconds,
            'ignore_errors' => true,
        ],
    ]);

    $body = @file_get_contents($url . '/auth/v1/health', false, $context);
    if ($body === false) {
        return null;
    }

    foreach ($http_response_header ?? [] as $header) {
        if (stripos($header, 'HTTP/') === 0) {
            $code = (int) substr($header, 9, 3);
            if (($code >= 200 && $code < 300) || $code === 401) {
                return 'ok';
            }
            return 'http-' . $code;
        }
    }

    return 'unknown';
}

$backend = supabaseReachable(SUPABASE_URL);
$backendLabel = match ($backend) {
    'ok'     => ['Backend online', '#34d399'],
    null     => ['Backend unreachable', '#f87171'],
    default  => ['Backend returned ' . $backend, '#fbbf24'],
};
?>
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Orvyn Cyber AI</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center;
    background: #0a0b14; color: #e5e7eb;
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  }
  main { width: min(34rem, 92vw); padding: 2rem 0; }
  h1 { font-size: 1.5rem; margin: 0 0 .25rem; letter-spacing: -.01em; }
  p.sub { color: #9ca3af; margin: 0 0 1.75rem; font-size: .9rem; }
  .card {
    border: 1px solid rgba(255,255,255,.07); border-radius: .75rem;
    padding: 1rem 1.25rem; background: #0d0f1a; margin-bottom: .75rem;
  }
  .row { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
  .key { font-size: .85rem; color: #9ca3af; }
  .val { font-size: .85rem; font-weight: 600; }
  .dot { display: inline-block; width: .5rem; height: .5rem; border-radius: 50%; margin-inline-end: .5rem; vertical-align: middle; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8rem; color: #cbd5e1; word-break: break-all; }
  a { color: #60a5fa; }
  footer { margin-top: 1.75rem; font-size: .75rem; color: #6b7280; }
</style>
</head>
<body>
<main>
  <h1>Orvyn Cyber AI</h1>
  <p class="sub">Web security scanning platform</p>

  <div class="card">
    <div class="row">
      <span class="key">Supabase backend</span>
      <span class="val"><span class="dot" style="background:<?= $backendLabel[1] ?>"></span><?= htmlspecialchars($backendLabel[0], ENT_QUOTES) ?></span>
    </div>
  </div>

  <div class="card">
    <div class="row">
      <span class="key">Project</span>
      <code><?= htmlspecialchars(SUPABASE_URL, ENT_QUOTES) ?></code>
    </div>
  </div>

  <div class="card">
    <div class="row">
      <span class="key">This host</span>
      <span class="val"><?= htmlspecialchars($_SERVER['SERVER_NAME'] ?? 'localhost', ENT_QUOTES) ?></span>
    </div>
  </div>

  <footer>
    Static frontend served from shared PHP hosting. Scanning runs on Supabase
    edge functions and the local agent. Set SUPABASE_URL in status.php after
    you create your project.
  </footer>
</main>
</body>
</html>
