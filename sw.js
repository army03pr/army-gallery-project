// Service Worker อย่างง่าย
self.addEventListener('install', (e) => {
    console.log('[Service Worker] Installed');
    self.skipWaiting(); // บังคับใช้ SW ตัวใหม่ทันที
});

self.addEventListener('activate', (e) => {
    console.log('[Service Worker] Activated');
    return self.clients.claim();
});

self.addEventListener('fetch', (e) => {
    // ปล่อยผ่านทุก Request (Online First) เพื่อให้ได้ข้อมูลล่าสุดเสมอ
    e.respondWith(fetch(e.request));
});