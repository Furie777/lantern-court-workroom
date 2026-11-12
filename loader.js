// Decrypts the room in the browser (WebCrypto AES-256-GCM, PBKDF2-SHA256) and runs it from memory. No network except same-origin ciphertext.
const $ = id => document.getElementById(id);
const norm = s => s.normalize('NFKC').trim().toLowerCase().replace(/[\s_]+/g, '-');
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const u32 = n => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
const msg = t => { $('msg').textContent = t; };
let busy = false;
$('f').addEventListener('submit', async e => {
  e.preventDefault(); if (busy) return; busy = true; $('go').disabled = true; msg('Checking…');
  try {
    const meta = await (await fetch('./meta.json', { cache: 'no-cache' })).json();
    const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(norm($('pw').value)), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: b64(meta.salt), iterations: meta.iter }, km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const dec = async (buf, idx) => crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12), additionalData: u32(idx) }, key, buf.slice(12));
    const get = async (idx, onbytes) => {
      const r = await fetch(`./d/${idx}.bin`); if (!r.ok) throw new Error('fetch ' + idx);
      const reader = r.body.getReader(), parts = []; let n = 0;
      for (;;) { const { done, value } = await reader.read(); if (done) break; parts.push(value); n += value.length; onbytes && onbytes(value.length); }
      const out = new Uint8Array(n); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out;
    };
    let manifest;
    try { manifest = JSON.parse(new TextDecoder().decode(await dec(await get(0), 0))); }
    catch (err) { msg('That passphrase did not work.'); $('pw').select(); busy = false; $('go').disabled = false; return; }
    const total = meta.sizes.reduce((a, b) => a + b, 0); let got = 0; $('bar').style.display = 'block';
    const tick = n => { got += n; $('bar').firstChild.style.width = Math.min(100, got / total * 100) + '%'; msg('Opening the room… ' + (got / 1048576).toFixed(1) + ' / ' + (total / 1048576).toFixed(1) + ' MB'); };
    const files = new Map();
    for (const f of manifest) {
      let plain = await dec(await get(f.idx, tick), f.idx);
      if (f.gz) plain = await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
      files.set(f.path, { type: f.type, data: plain });
    }
    // serve decrypted files to the app from memory
    const realFetch = window.fetch.bind(window);
    window.fetch = (input, init) => {
      const url = new URL(typeof input === 'string' ? input : (input.url || String(input)), location.href);
      const key = decodeURIComponent(url.pathname.slice(location.pathname.replace(/[^/]*$/, '').length));
      const f = files.get(key);
      if (f && url.origin === location.origin) return Promise.resolve(new Response(f.data.slice(0), { status: 200, headers: { 'Content-Type': f.type } }));
      return realFetch(input, init);
    };
    const html = new TextDecoder().decode(files.get('index.html').data);
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const js = [...doc.querySelectorAll('script[type=module]')].map(s => s.getAttribute('src').replace(/^\.\//, ''));
    doc.querySelectorAll('script').forEach(s => s.remove());
    document.getElementById('ldr').remove();
    doc.head.querySelectorAll('style').forEach(s => document.head.appendChild(document.importNode(s, true)));
    document.title = doc.title || 'Lantern Court';
    document.body.innerHTML = doc.body.innerHTML;
    for (const p of js) { const f = files.get(p); await import(/* @vite-ignore */ URL.createObjectURL(new Blob([f.data], { type: 'text/javascript' }))); }
  } catch (err) { console.error(err); msg('Something went wrong. Try again.'); busy = false; $('go').disabled = false; }
});
