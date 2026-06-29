/**
 * RiverForge Upload Worker — загрузка изображений на Cloudinary
 *
 * Env vars (wrangler secret put):
 *   CLOUDINARY_CLOUD      — Cloud name (например dmi3uacov)
 *   CLOUDINARY_API_KEY    — API Key
 *   CLOUDINARY_API_SECRET — API Secret
 *
 * Тело запроса: { image: "data:image/...", name: "filename", char_id: 42 }
 * Изображения складываются в папку: characters/{char_id}/
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }
    if (request.method !== 'POST') {
      return json({ success: false, error: 'method_not_allowed' }, 405);
    }

    let body;
    try { body = await request.json(); } catch {
      return json({ success: false, error: 'invalid_json' }, 400);
    }

    const dataUrl = body.image || '';
    const match = dataUrl.match(/^data:image\/([a-z+]+);base64,(.+)$/);
    if (!match) {
      return json({ success: false, error: 'invalid_image' }, 400);
    }

    const charId    = body.char_id ? String(body.char_id) : 'shared';
    const folder    = 'characters/' + charId;
    const timestamp = Math.floor(Date.now() / 1000);
    const apiKey    = (env.CLOUDINARY_API_KEY    || '').trim();
    const apiSecret = (env.CLOUDINARY_API_SECRET || '').trim();
    const cloud     = (env.CLOUDINARY_CLOUD      || '').trim();

    // SHA-1 подпись: folder и timestamp (алфавитный порядок: f < t)
    const paramsToSign = 'folder=' + folder + '&timestamp=' + timestamp;
    const signature = await sha1(paramsToSign + apiSecret);

    const form = new FormData();
    form.append('file',      dataUrl);
    form.append('api_key',   apiKey);
    form.append('timestamp', String(timestamp));
    form.append('folder',    folder);
    form.append('signature', signature);

    let res;
    try {
      res = await fetch(
        'https://api.cloudinary.com/v1_1/' + cloud + '/image/upload',
        { method: 'POST', body: form }
      );
    } catch (e) {
      return json({ success: false, error: 'network_error', detail: e.message }, 502);
    }

    let data;
    try { data = await res.json(); } catch {
      return json({ success: false, error: 'cloudinary_bad_response' }, 502);
    }

    if (!data.secure_url) {
      const msg = data.error && data.error.message ? data.error.message : JSON.stringify(data);
      return json({ success: false, error: msg }, 200);
    }

    const optimizedUrl = data.secure_url.replace('/upload/', '/upload/f_auto,q_auto/');
    return json({ success: true, link: optimizedUrl, public_id: data.public_id }, 200);
  },
};

async function sha1(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}
