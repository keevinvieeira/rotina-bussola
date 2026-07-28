/**
 * _worker.js — Bússola da Rotina (Cloudflare Workers)
 *
 * Dois objetivos:
 * 1. Proxy de /__/auth/* → bussula-da-rotina.firebaseapp.com (mesmo "origin" para Firebase Auth)
 * 2. Remove headers COOP/COEP que o Cloudflare Workers injeta e que quebram o popup do Google
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ── 1. Proxy do Firebase Auth Handler ──────────────────────────────────
    // O Firebase SDK (com authDomain = domínio atual) procura /__/auth/* no mesmo domínio.
    // Este worker intercepta e encaminha para o Firebase real, tornando tudo "same-origin".
    if (url.pathname.startsWith('/__/auth/')) {
      const firebaseUrl = `https://bussula-da-rotina.firebaseapp.com${url.pathname}${url.search}`;
      const proxyReq = new Request(firebaseUrl, {
        method: request.method,
        headers: request.headers,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
        redirect: 'follow',
      });
      return fetch(proxyReq);
    }

    // ── 2. Assets estáticos (index.html, etc.) com headers COOP removidos ──
    const response = await env.ASSETS.fetch(request);

    const newHeaders = new Headers(response.headers);
    // Remove os headers que quebram window.opener no Firebase signInWithPopup
    newHeaders.delete('Cross-Origin-Opener-Policy');
    newHeaders.delete('Cross-Origin-Embedder-Policy');

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    });
  },
};
