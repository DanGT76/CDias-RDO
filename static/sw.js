const CACHE_NAME = 'rdo-shell-v2';
const APP_SHELL = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png',
  '/icon-512-maskable.png',
  'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js'
];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(APP_SHELL))
      .catch(() => {})
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Chamadas de API nunca passam pelo cache — vão direto à rede.
  // O próprio app (index.html) trata falhas de rede com a fila offline.
  if (url.pathname.startsWith('/api/')) {
    return;
  }

  if (req.method !== 'GET') {
    return;
  }

  // Network-first: sempre tenta buscar a versão mais nova primeiro (assim toda
  // correção aparece de imediato) e só usa o cache como reserva se estiver
  // offline. Antes era cache-first, e por isso os últimos ajustes pareciam não
  // "pegar" no celular — o app mostrava a versão salva antes de checar a nova.
  event.respondWith(
    fetch(req)
      .then((res) => {
        if (res && res.status === 200) {
          const resClone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
        }
        return res;
      })
      .catch(() => caches.match(req))
  );
});
