// ──────────────────────────────────────────────────────────────────────────────
// RiverForge — Cloudflare Worker: Discord OAuth2 + JWT + KV персонажи
// Деплой: wrangler deploy
// Переменные окружения (wrangler secret put):
//   DISCORD_CLIENT_ID     — из Discord Developer Portal
//   DISCORD_CLIENT_SECRET — из Discord Developer Portal
//   JWT_SECRET            — любая длинная случайная строка
//   DISCORD_WEBHOOK_URL   — webhook URL канала для логов (опционально)
//   SUPER_ADMIN_ID        — Discord ID супер-админа (единственный кто назначает админов)
// KV binding: CHARS (namespace для персонажей и логов)
// ──────────────────────────────────────────────────────────────────────────────

export default {
    async fetch(request, env) {
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

// ── Вспомогательные: права и KV ──────────────────────────────────────────────

function isSuperAdmin(userId, env) {
    return !!(env.SUPER_ADMIN_ID && userId && env.SUPER_ADMIN_ID.trim() === String(userId).trim());
}

async function isAdmin(userId, env) {
    if (!userId) return false;
    if (isSuperAdmin(userId, env)) return true;
    var rec = await env.CHARS.get('admin:' + userId);
    return !!rec;
}

async function isBanned(userId, env) {
    if (!userId) return false;
    var rec = await env.CHARS.get('ban:' + userId);
    return !!rec;
}

async function getBanInfo(userId, env) {
    var raw = await env.CHARS.get('ban:' + userId);
    return raw ? JSON.parse(raw) : null;
}

async function addModLog(env, action, byId, byName, targetId, targetName, reason) {
    var raw = await env.CHARS.get('mod_log');
    var log = raw ? JSON.parse(raw) : [];
    log.unshift({ ts: Date.now(), action, by_id: byId, by_name: byName, target_id: targetId, target_name: targetName, reason: reason || '' });
    if (log.length > 1000) log = log.slice(0, 1000);
    await env.CHARS.put('mod_log', JSON.stringify(log));
}

async function updateUserRegistry(env, user) {
    await env.CHARS.put('user_info:' + user.discord_id, JSON.stringify({
        discord_id: user.discord_id,
        username:   user.username,
        avatar:     user.avatar || null,
        last_seen:  Date.now()
    }));
}

function jsonResp(data, status, corsHeaders) {
    return new Response(JSON.stringify(data), {
        status: status || 200,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
}

function json401(corsHeaders) {
    return jsonResp({ ok: false, error: 'unauthorized' }, 401, corsHeaders);
}

function json403(corsHeaders, reason) {
    return jsonResp({ ok: false, error: reason || 'forbidden' }, 403, corsHeaders);
}

// ── Основной роутер ───────────────────────────────────────────────────────────

async function handleRequest(request, env, corsHeaders) {
    var url = new URL(request.url);

    if (env.DISCORD_WEBHOOK_URL) {
        env = Object.assign({}, env, {
            DISCORD_WEBHOOK_URL: env.DISCORD_WEBHOOK_URL.replace(/^﻿/, '').trim()
        });
    }

    // GET /login
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
        return new Response(null, {
            status: 302,
            headers: {
                'Location':   authUrl,
                'Set-Cookie': `oauth_state=${state}; Max-Age=300; HttpOnly; Secure; SameSite=Lax`
            }
        });
    }

    // GET /callback
    if (url.pathname === '/callback') {
        var code = url.searchParams.get('code');
        if (!code) return Response.redirect(env.APP_URL + '?auth_error=no_code', 302);

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
        if (!tokenData.access_token) return Response.redirect(env.APP_URL + '?auth_error=token_failed', 302);

        var userRes = await fetch('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${tokenData.access_token}` }
        });
        var user = await userRes.json();
        if (!user.id) return Response.redirect(env.APP_URL + '?auth_error=user_failed', 302);

        // Проверяем бан до выдачи токена
        if (await isBanned(user.id, env)) {
            var banInfo = await getBanInfo(user.id, env);
            var reason = banInfo ? encodeURIComponent(banInfo.reason || 'нарушение правил') : 'banned';
            return Response.redirect(env.APP_URL + '?auth_error=banned&reason=' + reason, 302);
        }

        // Сохраняем пользователя в реестр
        await updateUserRegistry(env, { discord_id: user.id, username: user.username, avatar: user.avatar });

        var adminFlag = await isAdmin(user.id, env);
        var payload = {
            discord_id: user.id,
            username:   user.username,
            avatar:     user.avatar,
            is_admin:   adminFlag,
            iat:        Math.floor(Date.now() / 1000),
            exp:        Math.floor(Date.now() / 1000) + 15552000
        };
        var jwt = await signJWT(payload, env.JWT_SECRET);
        return Response.redirect(`${env.APP_URL}?token=${jwt}`, 302);
    }

    // GET /verify
    if (url.pathname === '/verify') {
        var authHeader = request.headers.get('Authorization') || '';
        var token      = authHeader.replace('Bearer ', '');
        var payload    = await verifyJWT(token, env.JWT_SECRET);
        if (!payload) return jsonResp({ ok: false }, 401, corsHeaders);
        if (await isBanned(payload.discord_id, env)) {
            var bi = await getBanInfo(payload.discord_id, env);
            return jsonResp({ ok: false, error: 'banned', reason: bi ? bi.reason : '' }, 403, corsHeaders);
        }
        // Обновляем is_admin в реальном времени
        var adminNow = await isAdmin(payload.discord_id, env);
        return jsonResp({ ok: true, user: Object.assign({}, payload, { is_admin: adminNow }) }, 200, corsHeaders);
    }

    // GET /chars/all — все персонажи + is_admin для авторизованного
    if (url.pathname === '/chars/all' && request.method === 'GET') {
        var authHeader = request.headers.get('Authorization') || '';
        var token      = authHeader.replace('Bearer ', '');
        var user       = token ? await verifyJWT(token, env.JWT_SECRET) : null;

        if (user && await isBanned(user.discord_id, env)) {
            var bi = await getBanInfo(user.discord_id, env);
            return jsonResp({ ok: false, error: 'banned', reason: bi ? bi.reason : '' }, 403, corsHeaders);
        }

        var list     = await env.CHARS.list({ prefix: 'chars:' });
        var allChars = [];
        for (var key of list.keys) {
            var data = await env.CHARS.get(key.name);
            if (data) {
                try { allChars = allChars.concat(JSON.parse(data)); } catch(e) {}
            }
        }

        var adminFlag = user ? await isAdmin(user.discord_id, env) : false;
        return jsonResp({ chars: allChars, is_admin: adminFlag }, 200, corsHeaders);
    }

    // GET /chars
    if (url.pathname === '/chars' && request.method === 'GET') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        var data = await env.CHARS.get('chars:' + user.discord_id);
        return new Response(data || '[]', { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // POST /chars/save
    if (url.pathname === '/chars/save' && request.method === 'POST') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);

        if (await isBanned(user.discord_id, env)) {
            var bi = await getBanInfo(user.discord_id, env);
            return jsonResp({ ok: false, error: 'banned', reason: bi ? bi.reason : '' }, 403, corsHeaders);
        }

        var body;
        try { body = await request.json(); } catch(e) {
            return jsonResp({ ok: false, error: 'bad_json' }, 400, corsHeaders);
        }

        var chars = body.chars || [];
        var meta  = body.meta  || {};

        var oldDataRaw = await env.CHARS.get('chars:' + user.discord_id);
        var oldChars   = oldDataRaw ? JSON.parse(oldDataRaw) : [];

        chars = chars.map(function(c) {
            return Object.assign({}, c, { owner_id: user.discord_id, owner_username: user.username });
        });

        await env.CHARS.put('chars:' + user.discord_id, JSON.stringify(chars));

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
        for (var oi = 0; oi < oldChars.length; oi++) {
            var oc = oldChars[oi];
            if (oc.id && !chars.find(function(c) { return c.id === oc.id; })) {
                await env.CHARS.delete('char_info:' + oc.id);
            }
        }

        var logsRaw = await env.CHARS.get('logs:' + user.discord_id);
        var logs    = logsRaw ? JSON.parse(logsRaw) : [];
        logs.unshift({ ts: Date.now(), char_id: meta.char_id || null, char_name: meta.char_name || '—', level: meta.level || '—', cls: meta.cls || '—', race: meta.race || '—', gold: meta.gold || 0, vladenie: meta.vladenie || {}, equipment_slots: meta.equipment_slots || [], skills_count: meta.skills_count || 0, magic_count: meta.magic_count || 0 });
        if (logs.length > 500) logs = logs.slice(0, 500);
        await env.CHARS.put('logs:' + user.discord_id, JSON.stringify(logs));

        if (env.DISCORD_WEBHOOK_URL) {
            try {
                var changes = []; var isNew = false;
                if (meta.char_id !== undefined) {
                    var newChar = chars.find(function(c) { return c.id === meta.char_id; });
                    var oldChar = oldChars.find(function(c) { return c.id === meta.char_id; });
                    if (!oldChar) { isNew = true; } else if (newChar) {
                        if ((oldChar.name||'') !== (newChar.name||'')) changes.push('📛 Имя: '+(oldChar.name||'—')+' → '+(newChar.name||'—'));
                        var og = oldChar.gold||0, ng = newChar.gold||0;
                        if (og !== ng) { var d=ng-og; changes.push((d>0?'🟡 +':'🔴 −')+Math.abs(d)+' золота ('+og+' → '+ng+')'); }
                        var oCls=oldChar.spec||oldChar.cls||'', nCls=newChar.spec||newChar.cls||'';
                        if (oCls!==nCls) changes.push('⚔️ Класс: '+(oCls||'—')+' → '+(nCls||'—'));
                        if ((oldChar.race||'')!==(newChar.race||'')) changes.push('🧬 Раса: '+(oldChar.race||'—')+' → '+(newChar.race||'—'));
                        var oSk=oldChar.skills||[],nSk=newChar.skills||[];
                        nSk.filter(function(s){return oSk.indexOf(s)<0;}).forEach(function(s){changes.push('📗 +навык: '+s);});
                        oSk.filter(function(s){return nSk.indexOf(s)<0;}).forEach(function(s){changes.push('📕 −навык: '+s);});
                        var oMg=oldChar.magic||[],nMg=newChar.magic||[];
                        nMg.filter(function(s){return oMg.indexOf(s)<0;}).forEach(function(s){changes.push('🔮 +заклинание: '+s);});
                        oMg.filter(function(s){return nMg.indexOf(s)<0;}).forEach(function(s){changes.push('🔮 −заклинание: '+s);});
                        var oSt=oldChar.stats||{},nSt=newChar.stats||{};
                        var allSK=Object.keys(Object.assign({},oSt,nSt));
                        var changedSt=allSK.filter(function(k){return (oSt[k]||0)!==(nSt[k]||0);}).map(function(k){return k+': '+(oSt[k]||0)+'→'+(nSt[k]||0);});
                        if (changedSt.length>0) changes.push('📊 Статы: '+changedSt.join(', '));
                        if (JSON.stringify(oldChar.equipment||{})!==JSON.stringify(newChar.equipment||{})) changes.push('🗡️ Изменено снаряжение');
                    }
                }
                var avatarUrl = user.avatar ? 'https://cdn.discordapp.com/avatars/'+user.discord_id+'/'+user.avatar+'.png?size=64' : undefined;
                var charLine = 'Ур.'+(meta.level||'—')+' · '+(meta.cls||'—')+' · '+(meta.race||'—');
                var goldLine = '🪙 '+(meta.gold||0);
                var embedColor, embedTitle, embedDesc;
                if (meta.gold_tx) {
                    var tx=meta.gold_tx, sign=tx.type==='income'?'+':'−', arrow=tx.type==='income'?'📥 Доход':'📤 Расход', label=tx.type==='income'?'Отправитель':'Получатель';
                    embedTitle=meta.char_name||'—'; embedDesc=charLine+'\n\n'+arrow+': '+sign+tx.amount+' 🪙\nПричина: '+(tx.reason||'—')+'\n'+label+': '+(tx.party||'Сторонние лица')+'\n\n'+goldLine;
                    embedColor=tx.type==='income'?0x43b581:0xf04747;
                } else {
                    var bodyStr=charLine; if(isNew){bodyStr+='\n\n✨ Новый персонаж';}else if(changes.length>0){bodyStr+='\n\n'+changes.join('\n');}else{bodyStr+='\n\nБез изменений';}
                    bodyStr+='\n\n'+goldLine; embedTitle=meta.char_name||'—'; embedDesc=bodyStr; embedColor=(isNew||changes.length>0)?0xfca311:0x5b6078;
                }
                var pingContent = (meta.gold_tx && meta.gold_tx.party_discord_id) ? '<@'+meta.gold_tx.party_discord_id+'>, тебе пришёл перевод!' : undefined;
                await fetch(env.DISCORD_WEBHOOK_URL, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ content:pingContent, username:user.username, avatar_url:avatarUrl, embeds:[{title:embedTitle,description:embedDesc,color:embedColor,timestamp:new Date().toISOString()}] }) });
            } catch(webhookErr) {}
        }

        if (meta.gold_tx && meta.gold_tx.party_char_id && meta.gold_tx.party_discord_id && meta.gold_tx.type==='expense') {
            try {
                var inboxKey='inbox:'+meta.gold_tx.party_char_id, inboxRaw=await env.CHARS.get(inboxKey), inbox=inboxRaw?JSON.parse(inboxRaw):[];
                inbox.push({ from_char_name:meta.char_name||user.username, from_owner_username:user.username, amount:meta.gold_tx.amount, reason:meta.gold_tx.reason||'—', ts:Date.now() });
                await env.CHARS.put(inboxKey, JSON.stringify(inbox));
            } catch(e) {}
        }

        return jsonResp({ ok: true }, 200, corsHeaders);
    }

    // GET /chars/search
    if (url.pathname === '/chars/search' && request.method === 'GET') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        var name = (url.searchParams.get('name') || '').trim().toLowerCase();
        if (name.length < 2) return jsonResp({ found: false, error: 'too_short' }, 200, corsHeaders);
        var list = await env.CHARS.list({ prefix: 'char_info:' });
        for (var ki = 0; ki < list.keys.length; ki++) {
            var raw = await env.CHARS.get(list.keys[ki].name);
            if (!raw) continue;
            var info = JSON.parse(raw);
            if (info.char_name && info.char_name.trim().toLowerCase() === name) {
                return jsonResp(Object.assign({ found: true }, info), 200, corsHeaders);
            }
        }
        return jsonResp({ found: false }, 200, corsHeaders);
    }

    // POST /gold/send
    if (url.pathname === '/gold/send' && request.method === 'POST') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        var body; try { body = await request.json(); } catch(e) { return jsonResp({ ok:false,error:'bad_json'},400,corsHeaders); }
        var toCharId=body.to_char_id, amount=parseInt(body.amount,10);
        if (!toCharId||!amount||amount<=0) return jsonResp({ok:false,error:'bad_params'},400,corsHeaders);
        var toInfoRaw=await env.CHARS.get('char_info:'+toCharId);
        if (!toInfoRaw) return jsonResp({ok:false,error:'char_not_found'},404,corsHeaders);
        var toInfo=JSON.parse(toInfoRaw);
        var inboxRaw=await env.CHARS.get('inbox:'+toCharId), inbox=inboxRaw?JSON.parse(inboxRaw):[];
        inbox.push({ from_char_name:body.from_char_name||user.username, from_owner_username:user.username, amount, reason:body.reason||'—', ts:Date.now() });
        await env.CHARS.put('inbox:'+toCharId, JSON.stringify(inbox));
        if (env.DISCORD_WEBHOOK_URL) { try { await fetch(env.DISCORD_WEBHOOK_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:'<@'+toInfo.owner_discord_id+'>, тебе пришёл перевод!',username:user.username,avatar_url:user.avatar?'https://cdn.discordapp.com/avatars/'+user.discord_id+'/'+user.avatar+'.png?size=64':undefined,embeds:[{title:toInfo.char_name,description:'📥 **+'+amount+' 🪙**\nОт: **'+(body.from_char_name||user.username)+'**\nПричина: '+(body.reason||'—'),color:0x43b581,timestamp:new Date().toISOString()}]})}); } catch(e) {} }
        return jsonResp({ ok: true }, 200, corsHeaders);
    }

    // POST /gold/inbox/claim
    if (url.pathname === '/gold/inbox/claim' && request.method === 'POST') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        var body; try { body = await request.json(); } catch(e) { return jsonResp({ok:false,error:'bad_json'},400,corsHeaders); }
        var charIds=Array.isArray(body.char_ids)?body.char_ids:[], credited=[];
        for (var i=0;i<charIds.length;i++) {
            var cid=charIds[i], inboxRaw=await env.CHARS.get('inbox:'+cid);
            if (!inboxRaw) continue;
            var entries=JSON.parse(inboxRaw); if(!entries.length) continue;
            var total=entries.reduce(function(s,e){return s+(e.amount||0);},0);
            credited.push({char_id:cid,entries,total}); await env.CHARS.delete('inbox:'+cid);
        }
        return jsonResp({ ok: true, credited }, 200, corsHeaders);
    }

    // GET /chars/logs
    if (url.pathname === '/chars/logs' && request.method === 'GET') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        var data = await env.CHARS.get('logs:' + user.discord_id);
        return new Response(data || '[]', { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // GET /admin/logs (старый эндпоинт через ADMIN_KEY)
    if (url.pathname === '/admin/logs' && request.method === 'GET') {
        if (env.ADMIN_KEY && url.searchParams.get('key') !== env.ADMIN_KEY) return json403(corsHeaders);
        var logsList=await env.CHARS.list({prefix:'logs:'}), allLogs=[];
        for (var lk of logsList.keys) {
            var discordId=lk.name.slice('logs:'.length), raw=await env.CHARS.get(lk.name);
            if (!raw) continue;
            var entries; try{entries=JSON.parse(raw);}catch(e){continue;}
            var playerName=discordId;
            try{var cr=await env.CHARS.get('chars:'+discordId);if(cr){var ch=JSON.parse(cr);if(ch.length>0&&ch[0].owner_username)playerName=ch[0].owner_username;}}catch(e){}
            entries.forEach(function(e){allLogs.push(Object.assign({},e,{player_id:discordId,player_name:playerName}));});
        }
        allLogs.sort(function(a,b){return (b.ts||0)-(a.ts||0);});
        return jsonResp(allLogs, 200, corsHeaders);
    }

    // ── ADMIN ENDPOINTS ───────────────────────────────────────────────────────

    // GET /admin/users — список всех пользователей
    if (url.pathname === '/admin/users' && request.method === 'GET') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        if (!await isAdmin(user.discord_id, env)) return json403(corsHeaders);
        var list = await env.CHARS.list({ prefix: 'user_info:' });
        var users = [];
        for (var k of list.keys) {
            var raw = await env.CHARS.get(k.name);
            if (!raw) continue;
            var u = JSON.parse(raw);
            var banned  = await isBanned(u.discord_id, env);
            var banInfo = banned ? await getBanInfo(u.discord_id, env) : null;
            var adminRec = await env.CHARS.get('admin:' + u.discord_id);
            users.push(Object.assign({}, u, {
                is_banned:   banned,
                ban_info:    banInfo,
                is_admin:    !!(adminRec || isSuperAdmin(u.discord_id, env)),
                is_super:    isSuperAdmin(u.discord_id, env)
            }));
        }
        users.sort(function(a, b) { return (b.last_seen || 0) - (a.last_seen || 0); });
        return jsonResp(users, 200, corsHeaders);
    }

    // POST /admin/ban
    if (url.pathname === '/admin/ban' && request.method === 'POST') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        if (!await isAdmin(user.discord_id, env)) return json403(corsHeaders);
        var body; try { body = await request.json(); } catch(e) { return jsonResp({ok:false,error:'bad_json'},400,corsHeaders); }
        var targetId = String(body.discord_id || '');
        var reason   = body.reason || 'нарушение правил';
        if (!targetId) return jsonResp({ok:false,error:'no_target'},400,corsHeaders);
        if (isSuperAdmin(targetId, env)) return json403(corsHeaders, 'cannot_ban_superadmin');
        // Получаем имя цели из реестра
        var targetInfoRaw = await env.CHARS.get('user_info:' + targetId);
        var targetName = targetInfoRaw ? (JSON.parse(targetInfoRaw).username || targetId) : targetId;
        await env.CHARS.put('ban:' + targetId, JSON.stringify({ reason, by_id: user.discord_id, by_name: user.username, at: Date.now() }));
        await addModLog(env, 'ban', user.discord_id, user.username, targetId, targetName, reason);
        return jsonResp({ ok: true }, 200, corsHeaders);
    }

    // POST /admin/unban
    if (url.pathname === '/admin/unban' && request.method === 'POST') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        if (!await isAdmin(user.discord_id, env)) return json403(corsHeaders);
        var body; try { body = await request.json(); } catch(e) { return jsonResp({ok:false,error:'bad_json'},400,corsHeaders); }
        var targetId = String(body.discord_id || '');
        if (!targetId) return jsonResp({ok:false,error:'no_target'},400,corsHeaders);
        var targetInfoRaw = await env.CHARS.get('user_info:' + targetId);
        var targetName = targetInfoRaw ? (JSON.parse(targetInfoRaw).username || targetId) : targetId;
        await env.CHARS.delete('ban:' + targetId);
        await addModLog(env, 'unban', user.discord_id, user.username, targetId, targetName, '');
        return jsonResp({ ok: true }, 200, corsHeaders);
    }

    // POST /admin/grant — выдать права админа (только супер-админ)
    if (url.pathname === '/admin/grant' && request.method === 'POST') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        if (!isSuperAdmin(user.discord_id, env)) return json403(corsHeaders);
        var body; try { body = await request.json(); } catch(e) { return jsonResp({ok:false,error:'bad_json'},400,corsHeaders); }
        var targetId = String(body.discord_id || '');
        if (!targetId) return jsonResp({ok:false,error:'no_target'},400,corsHeaders);
        var targetInfoRaw = await env.CHARS.get('user_info:' + targetId);
        var targetName = targetInfoRaw ? (JSON.parse(targetInfoRaw).username || targetId) : targetId;
        await env.CHARS.put('admin:' + targetId, JSON.stringify({ granted_by: user.discord_id, granted_at: Date.now() }));
        await addModLog(env, 'grant_admin', user.discord_id, user.username, targetId, targetName, '');
        return jsonResp({ ok: true }, 200, corsHeaders);
    }

    // POST /admin/revoke — забрать права админа (только супер-админ)
    if (url.pathname === '/admin/revoke' && request.method === 'POST') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        if (!isSuperAdmin(user.discord_id, env)) return json403(corsHeaders);
        var body; try { body = await request.json(); } catch(e) { return jsonResp({ok:false,error:'bad_json'},400,corsHeaders); }
        var targetId = String(body.discord_id || '');
        if (!targetId) return jsonResp({ok:false,error:'no_target'},400,corsHeaders);
        var targetInfoRaw = await env.CHARS.get('user_info:' + targetId);
        var targetName = targetInfoRaw ? (JSON.parse(targetInfoRaw).username || targetId) : targetId;
        await env.CHARS.delete('admin:' + targetId);
        await addModLog(env, 'revoke_admin', user.discord_id, user.username, targetId, targetName, '');
        return jsonResp({ ok: true }, 200, corsHeaders);
    }

    // POST /admin/force-logout — принудительный выход (сбрасывает токены старше now)
    if (url.pathname === '/admin/force-logout' && request.method === 'POST') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        if (!await isAdmin(user.discord_id, env)) return json403(corsHeaders);
        var body; try { body = await request.json(); } catch(e) { return jsonResp({ok:false,error:'bad_json'},400,corsHeaders); }
        var targetId = String(body.discord_id || '');
        if (!targetId) return jsonResp({ok:false,error:'no_target'},400,corsHeaders);
        if (isSuperAdmin(targetId, env)) return json403(corsHeaders, 'cannot_logout_superadmin');
        var targetInfoRaw = await env.CHARS.get('user_info:' + targetId);
        var targetName = targetInfoRaw ? (JSON.parse(targetInfoRaw).username || targetId) : targetId;
        // Сохраняем timestamp — все токены с iat < этого значения будут недействительны
        await env.CHARS.put('force_logout:' + targetId, String(Math.floor(Date.now() / 1000)));
        await addModLog(env, 'force_logout', user.discord_id, user.username, targetId, targetName, '');
        return jsonResp({ ok: true }, 200, corsHeaders);
    }

    // POST /admin/transfer-char — передать персонажа другому игроку
    if (url.pathname === '/admin/transfer-char' && request.method === 'POST') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        if (!await isAdmin(user.discord_id, env)) return json403(corsHeaders);
        var body; try { body = await request.json(); } catch(e) { return jsonResp({ok:false,error:'bad_json'},400,corsHeaders); }
        var charId = body.char_id, newOwnerId = String(body.new_owner_id || '');
        if (!charId || !newOwnerId) return jsonResp({ok:false,error:'bad_params'},400,corsHeaders);
        // Находим персонажа
        var charInfoRaw = await env.CHARS.get('char_info:' + charId);
        if (!charInfoRaw) return jsonResp({ok:false,error:'char_not_found'},404,corsHeaders);
        var charInfo = JSON.parse(charInfoRaw);
        var oldOwnerId = charInfo.owner_discord_id;
        // Перемещаем персонажа
        var oldCharsRaw = await env.CHARS.get('chars:' + oldOwnerId);
        var oldChars = oldCharsRaw ? JSON.parse(oldCharsRaw) : [];
        var charToMove = oldChars.find(function(c) { return c.id === charId; });
        if (!charToMove) return jsonResp({ok:false,error:'char_not_in_owner'},404,corsHeaders);
        // Удаляем из старого владельца
        var updatedOld = oldChars.filter(function(c) { return c.id !== charId; });
        await env.CHARS.put('chars:' + oldOwnerId, JSON.stringify(updatedOld));
        // Добавляем к новому владельцу
        var newOwnerInfoRaw = await env.CHARS.get('user_info:' + newOwnerId);
        var newOwnerName = newOwnerInfoRaw ? (JSON.parse(newOwnerInfoRaw).username || newOwnerId) : newOwnerId;
        var newCharsRaw = await env.CHARS.get('chars:' + newOwnerId);
        var newChars = newCharsRaw ? JSON.parse(newCharsRaw) : [];
        charToMove = Object.assign({}, charToMove, { owner_id: newOwnerId, owner_username: newOwnerName });
        newChars.push(charToMove);
        await env.CHARS.put('chars:' + newOwnerId, JSON.stringify(newChars));
        // Обновляем char_info
        await env.CHARS.put('char_info:' + charId, JSON.stringify(Object.assign({}, charInfo, { owner_discord_id: newOwnerId, owner_username: newOwnerName })));
        await addModLog(env, 'transfer_char', user.discord_id, user.username, charId, charInfo.char_name, oldOwnerId + ' → ' + newOwnerId);
        return jsonResp({ ok: true }, 200, corsHeaders);
    }

    // GET /admin/mod-log — лог модерации
    if (url.pathname === '/admin/mod-log' && request.method === 'GET') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        if (!await isAdmin(user.discord_id, env)) return json403(corsHeaders);
        var raw = await env.CHARS.get('mod_log');
        return new Response(raw || '[]', { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // POST /admin/cleanup-char-index
    if (url.pathname === '/admin/cleanup-char-index' && request.method === 'POST') {
        var user = await getUser(request, env);
        if (!user) return json401(corsHeaders);
        var list = await env.CHARS.list({ prefix: 'char_index:' });
        var deleted = 0;
        for (var ki = 0; ki < list.keys.length; ki++) { await env.CHARS.delete(list.keys[ki].name); deleted++; }
        return jsonResp({ ok: true, deleted }, 200, corsHeaders);
    }

    // GET /webhook/test
    if (url.pathname === '/webhook/test' && request.method === 'GET') {
        if (!env.DISCORD_WEBHOOK_URL) return jsonResp({ error: 'DISCORD_WEBHOOK_URL not set' }, 200, corsHeaders);
        try {
            var wr = await fetch(env.DISCORD_WEBHOOK_URL, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({content:'Webhook test from RiverForge Worker'}) });
            var wrText = await wr.text();
            return jsonResp({ status: wr.status, body: wrText, url_len: env.DISCORD_WEBHOOK_URL.length }, 200, corsHeaders);
        } catch(e) { return jsonResp({ error: e.message }, 500, corsHeaders); }
    }

    return new Response('RiverForge Auth Worker', { headers: corsHeaders });
}

// ── Вспомогательные: JWT и пользователь ──────────────────────────────────────

async function getUser(request, env) {
    var auth  = request.headers.get('Authorization') || '';
    var token = auth.replace('Bearer ', '');
    var payload = await verifyJWT(token, env.JWT_SECRET);
    if (!payload) return null;
    // Проверяем принудительный выход
    var forceLogoutTs = await env.CHARS.get('force_logout:' + payload.discord_id);
    if (forceLogoutTs && payload.iat < parseInt(forceLogoutTs, 10)) return null;
    return payload;
}

async function signJWT(payload, secret) {
    var header = { alg: 'HS256', typ: 'JWT' };
    var enc    = (obj) => btoa(JSON.stringify(obj)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    var data   = enc(header) + '.' + enc(payload);
    var key    = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
    var sig    = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
    var sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
    return data + '.' + sigB64;
}

async function verifyJWT(token, secret) {
    try {
        var parts   = token.split('.');
        if (parts.length !== 3) return null;
        var payload = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));
        if (payload.exp < Math.floor(Date.now() / 1000)) return null;
        var data    = parts[0] + '.' + parts[1];
        var key     = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['verify']);
        var sigBytes = Uint8Array.from(atob(parts[2].replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
        var valid   = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(data));
        return valid ? payload : null;
    } catch(e) { return null; }
}
