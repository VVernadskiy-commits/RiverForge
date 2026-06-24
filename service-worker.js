const CACHE_NAME = 'riverforge-v13';

// Файлы которые кешируются при установке
const PRECACHE_URLS = [
    '/RiverForge/',
    '/RiverForge/index.html',
    '/RiverForge/manifest.json',
    '/RiverForge/public/db.json',
    '/RiverForge/public/config.json'
];

// Установка: кешируем основные файлы
self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open(CACHE_NAME).then(function(cache) {
            return cache.addAll(PRECACHE_URLS);
        })
    );
    // Активируем новый SW сразу, не ждём закрытия вкладок
    self.skipWaiting();
});

// Активация: удаляем старые кеши
self.addEventListener('activate', function(event) {
    event.waitUntil(
        caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames
                    .filter(function(name) { return name !== CACHE_NAME; })
                    .map(function(name)   { return caches.delete(name); })
            );
        })
    );
    self.clients.claim();
});

// Стратегия: Network First с fallback на кеш
// Приложение всегда пытается получить свежую версию,
// при офлайне отдаёт закешированную
self.addEventListener('fetch', function(event) {
    // Не перехватываем запросы к внешним API (Discord, GAS, Cloudflare)
    var url = new URL(event.request.url);
    if (url.origin !== location.origin) return;

    event.respondWith(
        fetch(event.request)
            .then(function(response) {
                // Кешируем свежий ответ
                if (response.ok) {
                    var clone = response.clone();
                    caches.open(CACHE_NAME).then(function(cache) {
                        cache.put(event.request, clone);
                    });
                }
                return response;
            })
            .catch(function() {
                // Сеть недоступна — отдаём из кеша
                return caches.match(event.request)
                    .then(function(cached) {
                        return cached || caches.match('/RiverForge/index.html');
                    });
            })
    );
});
