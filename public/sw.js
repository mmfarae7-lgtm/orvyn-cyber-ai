/* Orvyn Cyber - service worker
 *
 * Enables "Add to Home Screen" / PWA install on Android & iOS.
 * Strategy:
 *   - App shell (index.html, manifest, icons) is precached once.
 *   - Navigations are network-first and fall back to the cached shell,
 *     so the app still opens offline (Supabase calls will fail, but the
 *     UI shell stays usable).
 *   - Hashed assets (assets/*.js, *.css) are cache-first after first fetch.
 *   - The status page and APK downloads are NEVER cached.
 *   - Cross-origin (Supabase API) requests are let through untouched, so
 *     no Authorization headers or user data are ever stored here.
 */

const CACHE = 'orvyn-v1';
const SHELL = [
  './',
  './index.html',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png',
];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(SHELL))
      .catch(() => {}) // non-fatal: installability only needs a controlled page
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key)))
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  let url;
  try {
    url = new URL(req.url);
  } catch {
    return;
  }
  if (url.origin !== self.location.origin) return; // leave Supabase API alone
  if (url.pathname.endsWith('/status.php')) return;
  if (url.pathname.includes('/downloads/')) return;

  // Navigation: network first, offline fallback to the cached shell.
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches
            .open(CACHE)
            .then((cache) => cache.put('./index.html', copy))
            .catch(() => {});
          return res;
        })
        .catch(() => caches.match('./index.html'))
    );
    return;
  }

  // Everything else same-origin: stale-while-revalidate.
  event.respondWith(
    caches.match(req).then((cached) => {
      const network = fetch(req)
        .then((res) => {
          if (res.ok) {
            const copy = res.clone();
            caches
              .open(CACHE)
              .then((cache) => cache.put(req, copy))
              .catch(() => {});
          }
          return res;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});