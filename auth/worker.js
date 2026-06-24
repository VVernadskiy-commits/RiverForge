// ──────────────────────────────────────────────────────────────────────────────
// RiverForge — Cloudflare Worker: Discord OAuth2 + JWT + KV персонажи
// Деплой: wrangler deploy
// Переменные окружения (wrangler secret put):
//   DISCORD_CLIENT_ID     — из Discord Developer Portal
//   DISCORD_CLIENT_SECRET — из Discord Developer Portal
//   JWT_SECRET            — любая длинная случайная строка
//   DISCORD_WEBHOOK_URL   — webhook URL канала для логов (опционально)
// KV binding: CHARS (namespace для персонажей и логов)
// ──────────────────────────────────────────────────────────────────────────────

export default {
    async fetch(request, env) {
        // CORS всегда возвращается, даже при 500
        var requestOrigin = request.headers.get('Origin') || '';
        var allowedOrigins = ['http://localhost:3001', 'http://localhost:8080'];
        if (env.APP_URL) allowedOrigins.push(new URL(env.APP_URL).origin);
        var corsOrigin = allowedOrigins.includes(requestOrigin) ? requestOrigin : (env.APP_URL ? new URL(env.APP_URL).origin : '*');
        var corsHeaders = {
            'Access-Control-Allow-Origin':  corsOrigin,
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization'
        };

        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        try {
        return await handleRequest(request, env, corsHeaders);
        } catch(e) {
            return new Response(JSON.stringify({ ok: false, error: e.message || String(e) }), {
                status: 500,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }
    }
};

async function handleRequest(request, env, corsHeaders) {
        var url = new URL(request.url);

        // Убираем BOM и пробелы из URL вебхука (PowerShell добавляет BOM при pipe)
        if (env.DISCORD_WEBHOOK_URL) {
            env = Object.assign({}, env, {
                DISCORD_WEBHOOK_URL: env.DISCORD_WEBHOOK_URL.replace(/^﻿/, '').trim()
            });
        }

        // GET /login — отдаём URL для редиректа на Discord
        if (url.pathname === '/login') {
            var state       = crypto.randomUUID();
            var redirectUri = url.origin + '/callback';
            var authUrl     = 'https://discord.com/oauth2/authorize?' + new URLSearchParams({
                client_id:     env.DISCORD_CLIENT_ID,
                redirect_uri:  redirectUri,
                response_type: 'code',
                scope:         'identify',
                state:         state
            });
            // state кладём в cookie на 5 минут (защита от CSRF), редиректим на Discord
            return new Response(null, {
                status: 302,
                headers: {
                    'Location':   authUrl,
                    'Set-Cookie': `oauth_state=${state}; Max-Age=300; HttpOnly; Secure; SameSite=Lax`
                }
            });
        }

        // GET /callback — Discord вернул code, обмениваем на JWT
        if (url.pathname === '/callback') {
            var code  = url.searchParams.get('code');
            var state = url.searchParams.get('state');

            if (!code) {
                return Response.redirect(env.APP_URL + '?auth_error=no_code', 302);
            }

            // Обмен code → access_token
            var tokenRes = await fetch('https://discord.com/api/oauth2/token', {
                method:  'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body:    new URLSearchParams({
                    client_id:     env.DISCORD_CLIENT_ID,
                    client_secret: env.DISCORD_CLIENT_SECRET,
                    grant_type:    'authorization_code',
                    code:          code,
                    redirect_uri:  url.origin + '/callback'
                })
            });
            var tokenData = await tokenRes.json();
            if (!tokenData.access_token) {
                return Response.redirect(env.APP_URL + '?auth_error=token_failed', 302);
            }

            // Получаем Discord профиль
            var userRes = await fetch('https://discord.com/api/users/@me', {
                headers: { Authorization: `Bearer ${tokenData.access_token}` }
            });
            var user = await userRes.json();
            if (!user.id) {
                return Response.redirect(env.APP_URL + '?auth_error=user_failed', 302);
            }

            // Подписываем JWT (HS256)
            var payload = {
                discord_id: user.id,
                username:   user.username,
                avatar:     user.avatar,
                iat:        Math.floor(Date.now() / 1000),
                exp:        Math.floor(Date.now() / 1000) + 15552000 // ~6 месяцев
            };
            var jwt = await signJWT(payload, env.JWT_SECRET);

            // Редиректим в приложение с токеном
            return Response.redirect(`${env.APP_URL}?token=${jwt}`, 302);
        }

        // GET /verify — фронтенд проверяет валидность токена
        if (url.pathname === '/verify') {
            var authHeader = request.headers.get('Authorization') || '';
            var token      = authHeader.replace('Bearer ', '');
            var payload    = await verifyJWT(token, env.JWT_SECRET);
            if (!payload) {
                return new Response(JSON.stringify({ ok: false }), {
                    status:  401,
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            return new Response(JSON.stringify({ ok: true, user: payload }), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // GET /chars/all — все персонажи всех игроков (без авторизации)
        if (url.pathname === '/chars/all' && request.method === 'GET') {
            var list = await env.CHARS.list({ prefix: 'chars:' });
            var allChars = [];
            for (var key of list.keys) {
                var data = await env.CHARS.get(key.name);
                if (data) {
                    try { allChars = allChars.concat(JSON.parse(data)); } catch(e) {}
                }
            }
            return new Response(JSON.stringify(allChars), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // GET /chars — загрузить персонажей авторизованного пользователя
        if (url.pathname === '/chars' && request.method === 'GET') {
            var user = await getUser(request, env);
            if (!user) return json401(corsHeaders);
            var data = await env.CHARS.get('chars:' + user.discord_id);
            return new Response(data || '[]', {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // POST /chars/save — сохранить персонажей, записать лог, отправить webhook
        if (url.pathname === '/chars/save' && request.method === 'POST') {
            var user = await getUser(request, env);
            if (!user) return json401(corsHeaders);

            var body;
            try { body = await request.json(); } catch(e) {
                return new Response(JSON.stringify({ ok: false, error: 'bad_json' }), {
                    status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }

            var chars = body.chars || [];
            var meta  = body.meta  || {};

            // Загружаем старые данные ДО сохранения — для diff
            var oldDataRaw = await env.CHARS.get('chars:' + user.discord_id);
            var oldChars   = oldDataRaw ? JSON.parse(oldDataRaw) : [];

            // Проставляем owner_id и owner_username на каждом персонаже
            chars = chars.map(function(c) {
                return Object.assign({}, c, { owner_id: user.discord_id, owner_username: user.username });
            });

            // Сохраняем персонажей
            await env.CHARS.put('chars:' + user.discord_id, JSON.stringify(chars));

            // Индексируем персонажей по char_id (имя не используется как ключ)
            for (var ci = 0; ci < chars.length; ci++) {
                var c = chars[ci];
                if (!c.id) continue;
                await env.CHARS.put('char_info:' + c.id, JSON.stringify({
                    char_id:          c.id,
                    char_name:        c.name  || '—',
                    owner_discord_id: user.discord_id,
                    owner_username:   user.username,
                    cls:              c.spec  || c.cls || '—',
                    race:             c.race  || '—'
                }));
            }
            // Удаляем char_info для удалённых персонажей
            for (var oi = 0; oi < oldChars.length; oi++) {
                var oc = oldChars[oi];
                if (oc.id && !chars.find(function(c) { return c.id === oc.id; })) {
                    await env.CHARS.delete('char_info:' + oc.id);
                }
            }

            // Обновляем лог игрока (cap 500)
            var logsRaw  = await env.CHARS.get('logs:' + user.discord_id);
            var logs     = logsRaw ? JSON.parse(logsRaw) : [];
            logs.unshift({
                ts:        Date.now(),
                char_id:   meta.char_id   || null,
                char_name: meta.char_name || '—',
                level:     meta.level     || '—',
                cls:       meta.cls       || '—',
                race:      meta.race      || '—',
                gold:      meta.gold      || 0
            });
            if (logs.length > 500) logs = logs.slice(0, 500);
            await env.CHARS.put('logs:' + user.discord_id, JSON.stringify(logs));

            // Discord webhook (если настроен) — не роняем сохранение при ошибке вебхука
            if (env.DISCORD_WEBHOOK_URL) {
                try {
                // Строим diff активного персонажа
                var changes = [];
                var isNew   = false;
                if (meta.char_id !== undefined) {
                    var newChar = chars.find(function(c) { return c.id === meta.char_id; });
                    var oldChar = oldChars.find(function(c) { return c.id === meta.char_id; });
                    if (!oldChar) {
                        isNew = true;
                    } else if (newChar) {
                        if ((oldChar.name || '') !== (newChar.name || ''))
                            changes.push('📛 Имя: ' + (oldChar.name || '—') + ' → ' + (newChar.name || '—'));
                        var og = oldChar.gold || 0, ng = newChar.gold || 0;
                        if (og !== ng) {
                            var d = ng - og;
                            changes.push((d > 0 ? '🟡 +' : '🔴 −') + Math.abs(d) + ' золота (' + og + ' → ' + ng + ')');
                        }
                        var oCls = oldChar.spec || oldChar.cls || '';
                        var nCls = newChar.spec || newChar.cls || '';
                        if (oCls !== nCls) changes.push('⚔️ Класс: ' + (oCls || '—') + ' → ' + (nCls || '—'));
                        if ((oldChar.race || '') !== (newChar.race || ''))
                            changes.push('🧬 Раса: ' + (oldChar.race || '—') + ' → ' + (newChar.race || '—'));
                        var oSk = oldChar.skills || [], nSk = newChar.skills || [];
                        nSk.filter(function(s){return oSk.indexOf(s)<0;}).forEach(function(s){changes.push('📗 +навык: '+s);});
                        oSk.filter(function(s){return nSk.indexOf(s)<0;}).forEach(function(s){changes.push('📕 −навык: '+s);});
                        var oMg = oldChar.magic || [], nMg = newChar.magic || [];
                        nMg.filter(function(s){return oMg.indexOf(s)<0;}).forEach(function(s){changes.push('🔮 +заклинание: '+s);});
                        oMg.filter(function(s){return nMg.indexOf(s)<0;}).forEach(function(s){changes.push('🔮 −заклинание: '+s);});
                        // Изменения числовых статов
                        var oSt = oldChar.stats || {}, nSt = newChar.stats || {};
                        var allSK = Object.keys(Object.assign({}, oSt, nSt));
                        var changedSt = allSK.filter(function(k){ return (oSt[k]||0) !== (nSt[k]||0); })
                            .map(function(k){ return k+': '+(oSt[k]||0)+'→'+(nSt[k]||0); });
                        if (changedSt.length > 0) changes.push('📊 Статы: ' + changedSt.join(', '));
                        // Изменения снаряжения
                        if (JSON.stringify(oldChar.equipment||{}) !== JSON.stringify(newChar.equipment||{}))
                            changes.push('🗡️ Изменено снаряжение');
                    }
                }

                var avatarUrl = user.avatar
                    ? 'https://cdn.discordapp.com/avatars/' + user.discord_id + '/' + user.avatar + '.png?size=64'
                    : undefined;

                var charLine = 'Ур. ' + (meta.level || '—') + '  ·  ' + (meta.cls || '—') + '  ·  ' + (meta.race || '—');
                var goldLine = '🪙 ' + (meta.gold || 0);
                var embedColor, embedTitle, embedDesc;

                if (meta.gold_tx) {
                    // Транзакция из «Квитанции»
                    var tx = meta.gold_tx;
                    var sign  = tx.type === 'income' ? '+' : '−';
                    var arrow = tx.type === 'income' ? '📥 Доход' : '📤 Расход';
                    var label = tx.type === 'income' ? 'Отправитель' : 'Получатель';
                    embedTitle = meta.char_name || '—';
                    embedDesc  = charLine
                        + '\n\n' + arrow + ': ' + sign + tx.amount + ' 🪙'
                        + '\nПричина: ' + (tx.reason || '—')
                        + '\n' + label + ': ' + (tx.party || 'Сторонние лица')
                        + '\n\n' + goldLine;
                    embedColor = tx.type === 'income' ? 0x43b581 : 0xf04747;
                } else {
                    // Обычное сохранение — показываем diff
                    var body = charLine;
                    if (isNew) {
                        body += '\n\n✨ Новый персонаж';
                    } else if (changes.length > 0) {
                        body += '\n\n' + changes.join('\n');
                    } else {
                        body += '\n\nБез изменений';
                    }
                    body += '\n\n' + goldLine;
                    embedTitle = meta.char_name || '—';
                    embedDesc  = body;
                    embedColor = (isNew || changes.length > 0) ? 0xfca311 : 0x5b6078;
                }

                // Пинг получателя если это cross-user перевод
                var pingContent = (meta.gold_tx && meta.gold_tx.party_discord_id)
                    ? '<@' + meta.gold_tx.party_discord_id + '>, тебе пришёл перевод!'
                    : undefined;

                await fetch(env.DISCORD_WEBHOOK_URL, {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body:    JSON.stringify({
                        content:    pingContent,
                        username:   user.username,
                        avatar_url: avatarUrl,
                        embeds: [{
                            title:       embedTitle,
                            description: embedDesc,
                            color:       embedColor,
                            timestamp:   new Date().toISOString()
                        }]
                    })
                });
                } catch(webhookErr) { /* не роняем сохранение */ }
            }

            // Inbox для cross-user расхода (записываем после webhook чтобы не блокировать)
            if (meta.gold_tx && meta.gold_tx.party_char_id && meta.gold_tx.party_discord_id
                    && meta.gold_tx.type === 'expense') {
                try {
                    var inboxKey = 'inbox:' + meta.gold_tx.party_char_id;
                    var inboxRaw = await env.CHARS.get(inboxKey);
                    var inbox    = inboxRaw ? JSON.parse(inboxRaw) : [];
                    inbox.push({
                        from_char_name:      meta.char_name || user.username,
                        from_owner_username: user.username,
                        amount:  meta.gold_tx.amount,
                        reason:  meta.gold_tx.reason || '—',
                        ts:      Date.now()
                    });
                    await env.CHARS.put(inboxKey, JSON.stringify(inbox));
                } catch(e) { /* не роняем */ }
            }

            return new Response(JSON.stringify({ ok: true }), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // GET /chars/search?name=X — поиск персонажа по имени через скан char_info:*
        if (url.pathname === '/chars/search' && request.method === 'GET') {
            var user = await getUser(request, env);
            if (!user) return json401(corsHeaders);
            var name = (url.searchParams.get('name') || '').trim().toLowerCase();
            if (name.length < 2) {
                return new Response(JSON.stringify({ found: false, error: 'too_short' }), {
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            var list = await env.CHARS.list({ prefix: 'char_info:' });
            for (var ki = 0; ki < list.keys.length; ki++) {
                var raw = await env.CHARS.get(list.keys[ki].name);
                if (!raw) continue;
                var info = JSON.parse(raw);
                if (info.char_name && info.char_name.trim().toLowerCase() === name) {
                    return new Response(JSON.stringify(Object.assign({ found: true }, info)), {
                        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                    });
                }
            }
            return new Response(JSON.stringify({ found: false }), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // POST /gold/send — отправить золото персонажу другого игрока
        if (url.pathname === '/gold/send' && request.method === 'POST') {
            var user = await getUser(request, env);
            if (!user) return json401(corsHeaders);
            var body;
            try { body = await request.json(); } catch(e) {
                return new Response(JSON.stringify({ ok: false, error: 'bad_json' }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }
            var toCharId = body.to_char_id;
            var amount   = parseInt(body.amount, 10);
            if (!toCharId || !amount || amount <= 0) {
                return new Response(JSON.stringify({ ok: false, error: 'bad_params' }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }
            var toInfoRaw = await env.CHARS.get('char_info:' + toCharId);
            if (!toInfoRaw) {
                return new Response(JSON.stringify({ ok: false, error: 'char_not_found' }), { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }
            var toInfo = JSON.parse(toInfoRaw);
            // Кладём в inbox получателя
            var inboxRaw = await env.CHARS.get('inbox:' + toCharId);
            var inbox    = inboxRaw ? JSON.parse(inboxRaw) : [];
            inbox.push({
                from_char_name:      body.from_char_name || user.username,
                from_owner_username: user.username,
                amount:  amount,
                reason:  body.reason || '—',
                ts:      Date.now()
            });
            await env.CHARS.put('inbox:' + toCharId, JSON.stringify(inbox));
            // Discord-уведомление с @-упоминанием получателя
            if (env.DISCORD_WEBHOOK_URL) {
                try {
                    await fetch(env.DISCORD_WEBHOOK_URL, {
                        method:  'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            content:    '<@' + toInfo.owner_discord_id + '>, тебе пришёл перевод!',
                            username:   user.username,
                            avatar_url: user.avatar
                                ? 'https://cdn.discordapp.com/avatars/' + user.discord_id + '/' + user.avatar + '.png?size=64'
                                : undefined,
                            embeds: [{
                                title:       toInfo.char_name,
                                description: '📥 **+' + amount + ' 🪙**'
                                    + '\nОт: **' + (body.from_char_name || user.username) + '**'
                                    + '\nПричина: ' + (body.reason || '—'),
                                color:     0x43b581,
                                timestamp: new Date().toISOString()
                            }]
                        })
                    });
                } catch(e) { /* не роняем */ }
            }
            return new Response(JSON.stringify({ ok: true }), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // POST /gold/inbox/claim — забрать входящие переводы
        if (url.pathname === '/gold/inbox/claim' && request.method === 'POST') {
            var user = await getUser(request, env);
            if (!user) return json401(corsHeaders);
            var body;
            try { body = await request.json(); } catch(e) {
                return new Response(JSON.stringify({ ok: false, error: 'bad_json' }), { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
            }
            var charIds  = Array.isArray(body.char_ids) ? body.char_ids : [];
            var credited = [];
            for (var i = 0; i < charIds.length; i++) {
                var cid      = charIds[i];
                var inboxRaw = await env.CHARS.get('inbox:' + cid);
                if (!inboxRaw) continue;
                var entries = JSON.parse(inboxRaw);
                if (!entries.length) continue;
                var total = entries.reduce(function(s, e) { return s + (e.amount || 0); }, 0);
                credited.push({ char_id: cid, entries: entries, total: total });
                await env.CHARS.delete('inbox:' + cid);
            }
            return new Response(JSON.stringify({ ok: true, credited: credited }), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // POST /admin/cleanup-char-index — удалить устаревшие char_index:* ключи (одноразово)
        if (url.pathname === '/admin/cleanup-char-index' && request.method === 'POST') {
            var user = await getUser(request, env);
            if (!user) return json401(corsHeaders);
            var list = await env.CHARS.list({ prefix: 'char_index:' });
            var deleted = 0;
            for (var ki = 0; ki < list.keys.length; ki++) {
                await env.CHARS.delete(list.keys[ki].name);
                deleted++;
            }
            return new Response(JSON.stringify({ ok: true, deleted: deleted }), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // GET /webhook/test — диагностика Discord-вебхука (временный эндпоинт)
        if (url.pathname === '/webhook/test' && request.method === 'GET') {
            if (!env.DISCORD_WEBHOOK_URL) {
                return new Response(JSON.stringify({ error: 'DISCORD_WEBHOOK_URL not set' }), {
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            try {
                var wr = await fetch(env.DISCORD_WEBHOOK_URL, {
                    method:  'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body:    JSON.stringify({ content: 'Webhook test from RiverForge Worker' })
                });
                var wrText = await wr.text();
                return new Response(JSON.stringify({ status: wr.status, body: wrText, url_len: env.DISCORD_WEBHOOK_URL.length }), {
                    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            } catch(e) {
                return new Response(JSON.stringify({ error: e.message, url_len: env.DISCORD_WEBHOOK_URL.length }), {
                    status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
        }

        // GET /chars/logs — получить лог изменений игрока
        if (url.pathname === '/chars/logs' && request.method === 'GET') {
            var user = await getUser(request, env);
            if (!user) return json401(corsHeaders);
            var data = await env.CHARS.get('logs:' + user.discord_id);
            return new Response(data || '[]', {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        // GET /admin/logs — все логи всех игроков (требует ADMIN_KEY)
        if (url.pathname === '/admin/logs' && request.method === 'GET') {
            if (env.ADMIN_KEY && url.searchParams.get('key') !== env.ADMIN_KEY) {
                return new Response(JSON.stringify({ ok: false, error: 'forbidden' }), {
                    status: 403, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
                });
            }
            var logsList = await env.CHARS.list({ prefix: 'logs:' });
            var allLogs  = [];
            for (var lk of logsList.keys) {
                var discordId = lk.name.slice('logs:'.length);
                var raw = await env.CHARS.get(lk.name);
                if (!raw) continue;
                var entries;
                try { entries = JSON.parse(raw); } catch(e) { continue; }
                // Получаем имя игрока из первого персонажа
                var playerName = discordId;
                try {
                    var charsRaw = await env.CHARS.get('chars:' + discordId);
                    if (charsRaw) {
                        var chars = JSON.parse(charsRaw);
                        if (chars.length > 0 && chars[0].owner_username) playerName = chars[0].owner_username;
                    }
                } catch(e) {}
                entries.forEach(function(e) {
                    allLogs.push(Object.assign({}, e, { player_id: discordId, player_name: playerName }));
                });
            }
            allLogs.sort(function(a, b) { return (b.ts || 0) - (a.ts || 0); });
            return new Response(JSON.stringify(allLogs), {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' }
            });
        }

        return new Response('RiverForge Auth Worker', { headers: corsHeaders });
}

function json401(corsHeaders) {
    return new Response(JSON.stringify({ ok: false, error: 'unauthorized' }), {
        status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
}

async function getUser(request, env) {
    var auth  = request.headers.get('Authorization') || '';
    var token = auth.replace('Bearer ', '');
    return await verifyJWT(token, env.JWT_SECRET);
}

// ── JWT утилиты (HS256) ───────────────────────────────────────────────────────

async function signJWT(payload, secret) {
    var header  = { alg: 'HS256', typ: 'JWT' };
    var enc     = (obj) => btoa(JSON.stringify(obj)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    var data    = enc(header) + '.' + enc(payload);
    var key     = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    var sig     = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
    var sigB64  = btoa(String.fromCharCode(...new Uint8Array(sig)))
                    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    return data + '.' + sigB64;
}

async function verifyJWT(token, secret) {
    try {
        var parts = token.split('.');
        if (parts.length !== 3) return null;
        var payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        if (payload.exp < Math.floor(Date.now() / 1000)) return null;
        var data    = parts[0] + '.' + parts[1];
        var key     = await crypto.subtle.importKey(
            'raw', new TextEncoder().encode(secret),
            { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
        );
        var sigBytes = Uint8Array.from(atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
        var valid    = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(data));
        return valid ? payload : null;
    } catch (e) {
        return null;
    }
}
