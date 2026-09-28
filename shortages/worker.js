const ROLES = ['admin', 'purchasing', 'warehouse'];
const STATUSES = ['pending', 'purchased', 'completed'];
const enc = new TextEncoder();
const dec = new TextDecoder();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'access-control-allow-origin': '*',
      'access-control-allow-headers': 'authorization,content-type',
      'access-control-allow-methods': 'GET,POST,PATCH,DELETE,OPTIONS'
    }
  });
}

const fail = (msg, status = 400) => json({ error: msg }, status);
const now = () => new Date().toISOString().replace('T', ' ').slice(0, 19);
const mkId = (p) => `${p}_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;

function b64url(bytes) {
  let s = '';
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i++) s += String.fromCharCode(view[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64url(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function unhex(h) {
  return new Uint8Array((h.match(/.{2}/g) || []).map((x) => parseInt(x, 16)));
}

const toHex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64url(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

async function makeToken(payload, secret) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  return `${body}.${await hmac(secret, body)}`;
}

async function readToken(token, secret) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const idx = token.lastIndexOf('.');
  const body = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expected = await hmac(secret, body);
  if (sig.length !== expected.length) return null;
  let diff = 0;
  for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
  if (diff !== 0) return null;
  try {
    const payload = JSON.parse(dec.decode(unb64url(body)));
    if (!payload.exp || Number(payload.exp) < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

async function hashPassword(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return `pbkdf2$${toHex(salt)}$${toHex(bits)}`;
}

async function verifyPassword(pw, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 3 || parts[0] !== 'pbkdf2') return false;
  const key = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unhex(parts[1]), iterations: 100000, hash: 'SHA-256' }, key, 256);
  return toHex(bits) === parts[2];
}

const sessionSecret = (env) => env.SESSION_SECRET || 'mankhul-shortages-dev-secret';
const publicUser = (u) => ({ id: u.id, name: u.name, username: u.username, role: u.role, created_at: u.created_at });

const num = (v, fallback = 0) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
};
const str = (v, fallback = '') => (typeof v === 'string' ? v.trim() : fallback);
const clampText = (v, max = 500) => str(v).slice(0, max);

async function currentUser(request, env) {
  const header = request.headers.get('authorization') || '';
  const url = new URL(request.url);
  const token = header.startsWith('Bearer ') ? header.slice(7).trim() : url.searchParams.get('token');
  const payload = await readToken(token, sessionSecret(env));
  if (!payload) return null;
  return env.DB.prepare('SELECT id,name,username,role,created_at FROM users WHERE id=?').bind(payload.uid).first();
}

async function notify(env, title, body, targetRole) {
  await env.DB
    .prepare('INSERT INTO notifications (id,title,body,target_role,created_at) VALUES (?,?,?,?,?)')
    .bind(mkId('ntf'), title, clampText(body, 300), targetRole, now())
    .run();
}

async function readJson(request) {
  try {
    const data = await request.json();
    return data && typeof data === 'object' ? data : {};
  } catch {
    return {};
  }
}

async function handleApi(request, env, url) {
  const { pathname } = url;
  const method = request.method.toUpperCase();

  if (method === 'OPTIONS') return new Response(null, { status: 204, headers: json({}, 200).headers });

  if (pathname === '/api/health') {
    const row = await env.DB.prepare('SELECT COUNT(*) AS c FROM users').first();
    return json({ ok: true, users: row?.c ?? 0, time: now() });
  }

  if (pathname === '/api/login' && method === 'POST') {
    const { username, password } = await readJson(request);
    const uname = str(username);
    if (!uname || !password) return fail('اسم المستخدم وكلمة المرور مطلوبان');
    const row = await env.DB.prepare('SELECT * FROM users WHERE username=?').bind(uname).first();
    if (!row) return fail('بيانات الدخول غير صحيحة', 401);
    const legacy = typeof row.password === 'string' && !row.password.startsWith('pbkdf2$');
    const ok = legacy ? row.password === password : await verifyPassword(password, row.password);
    if (!ok) return fail('بيانات الدخول غير صحيحة', 401);
    if (legacy) {
      await env.DB.prepare('UPDATE users SET password=? WHERE id=?').bind(await hashPassword(password), row.id).run();
    }
    const token = await makeToken({ uid: row.id, exp: Date.now() + 30 * 24 * 3600 * 1000 }, sessionSecret(env));
    return json({ token, user: publicUser(row) });
  }

  const user = await currentUser(request, env);
  if (!user) return fail('غير مصرح، سجّل دخول من جديد', 401);

  if (pathname === '/api/me' && method === 'GET') return json({ user });

  if (pathname === '/api/users') {
    if (method === 'GET') {
      const { results } = await env.DB.prepare('SELECT id,name,username,role,created_at FROM users ORDER BY created_at').all();
      return json({ users: results });
    }
    if (method === 'POST') {
      if (user.role !== 'admin') return fail('هذه العملية للمدير فقط', 403);
      const b = await readJson(request);
      const name = clampText(b.name, 80);
      const username = clampText(b.username, 40).toLowerCase();
      const password = typeof b.password === 'string' ? b.password : '';
      const role = str(b.role, 'warehouse');
      if (!name || !username || password.length < 4) return fail('الاسم واسم المستخدم وكلمة مرور (٤ أحرف على الأقل) مطلوبة');
      if (!ROLES.includes(role)) return fail('دور غير صحيح');
      const dup = await env.DB.prepare('SELECT id FROM users WHERE username=?').bind(username).first();
      if (dup) return fail('اسم المستخدم مستخدم مسبقاً', 409);
      const newUser = { id: mkId('usr'), name, username, role, created_at: now() };
      await env.DB
        .prepare('INSERT INTO users (id,name,username,password,role,created_at) VALUES (?,?,?,?,?,?)')
        .bind(newUser.id, name, username, await hashPassword(password), role, newUser.created_at)
        .run();
      await notify(env, 'مستخدم جديد 👤', `${name} انضم كفريق العمل`, 'all');
      return json({ user: newUser }, 201);
    }
  }

  const userMatch = pathname.match(/^\/api\/users\/([A-Za-z0-9_]+)$/);
  if (userMatch) {
    if (user.role !== 'admin') return fail('هذه العملية للمدير فقط', 403);
    const targetId = userMatch[1];
    if (method === 'DELETE') {
      if (targetId === user.id) return fail('ماتقدر تحذف حسابك');
      const res = await env.DB.prepare('DELETE FROM users WHERE id=?').bind(targetId).run();
      if (!res.meta?.changes) return fail('المستخدم غير موجود', 404);
      return json({ ok: true });
    }
    if (method === 'PATCH') {
      const b = await readJson(request);
      const target = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(targetId).first();
      if (!target) return fail('المستخدم غير موجود', 404);
      const name = b.name != null ? clampText(b.name, 80) : target.name;
      const role = b.role != null ? str(b.role, target.role) : target.role;
      if (!ROLES.includes(role)) return fail('دور غير صحيح');
      if (b.password) {
        await env.DB.prepare('UPDATE users SET name=?, role=?, password=? WHERE id=?')
          .bind(name, role, await hashPassword(String(b.password)), targetId).run();
      } else {
        await env.DB.prepare('UPDATE users SET name=?, role=? WHERE id=?').bind(name, role, targetId).run();
      }
      return json({ ok: true, user: { id: targetId, name, username: target.username, role } });
    }
  }

  if (pathname === '/api/items') {
    if (method === 'GET') {
      const { results } = await env.DB.prepare('SELECT * FROM items ORDER BY created_at DESC').all();
      return json({ items: results });
    }
    if (method === 'POST') {
      if (!['warehouse', 'admin'].includes(user.role)) return fail('تقرير النواقص من المخزن أو المدير', 403);
      const b = await readJson(request);
      const name = clampText(b.name, 120);
      if (!name) return fail('اسم المادة مطلوب');
      const quantity = num(b.quantity, 0);
      if (quantity <= 0) return fail('الكمية مطلوبة');
      const priority = b.priority === 'urgent' ? 'urgent' : 'normal';
      const item = {
        id: mkId('itm'),
        name,
        quantity,
        unit: clampText(b.unit, 20) || 'قطعة',
        notes: clampText(b.notes),
        status: 'pending',
        quantity_purchased: 0,
        missing_reason: clampText(b.missing_reason, 300),
        created_by: user.id,
        created_at: now(),
        received_quantity: 0,
        priority,
        price: 0,
        supplier: ''
      };
      await env.DB
        .prepare(
          `INSERT INTO items (id,name,quantity,unit,notes,status,quantity_purchased,missing_reason,inventory_notes,
             created_by,purchased_by,confirmed_by,created_at,purchased_at,completed_at,received_quantity,priority,price,supplier)
           VALUES (?,?,?,?,?,'pending',0,?,'',?,NULL,NULL,?,NULL,NULL,0,?,0,'')`
        )
        .bind(
          item.id, item.name, item.quantity, item.unit, item.notes, item.missing_reason,
          item.created_by, item.created_at, item.priority
        )
        .run();
      await notify(
        env,
        priority === 'urgent' ? '⚡ نقص مهم في المخزن!' : 'نقص جديد في المخزن! 📦',
        `${name} — الكمية ${item.quantity} ${item.unit}`,
        'purchasing'
      );
      return json({ item }, 201);
    }
  }

  const itemMatch = pathname.match(/^\/api\/items\/([A-Za-z0-9_]+)$/);
  if (itemMatch) {
    const itemId = itemMatch[1];
    const current = await env.DB.prepare('SELECT * FROM items WHERE id=?').bind(itemId).first();
    if (!current) return fail('العنصر غير موجود', 404);

    if (method === 'DELETE') {
      if (user.role !== 'admin') return fail('الحذف للمدير فقط', 403);
      await env.DB.prepare('DELETE FROM items WHERE id=?').bind(itemId).run();
      return json({ ok: true });
    }

    if (method === 'PATCH') {
      const b = await readJson(request);
      const sets = [];
      const vals = [];
      const push = (col, val) => {
        sets.push(`${col}=?`);
        vals.push(val);
      };
      let transition = null;

      if (['warehouse', 'admin'].includes(user.role)) {
        if (b.notes != null) push('notes', clampText(b.notes));
        if (b.priority != null) push('priority', b.priority === 'urgent' ? 'urgent' : 'normal');
      }
      if (['purchasing', 'admin'].includes(user.role)) {
        if (b.quantity_purchased != null) push('quantity_purchased', Math.max(0, num(b.quantity_purchased)));
        if (b.price != null) push('price', Math.max(0, num(b.price)));
        if (b.supplier != null) push('supplier', clampText(b.supplier, 120));
      }
      if (['warehouse', 'admin'].includes(user.role) && b.received_quantity != null) {
        push('received_quantity', Math.max(0, num(b.received_quantity)));
      }
      if (['warehouse', 'admin'].includes(user.role) && b.inventory_notes != null) {
        push('inventory_notes', clampText(b.inventory_notes));
      }

      if (b.status && b.status !== current.status) {
        if (!STATUSES.includes(b.status)) return fail('حالة غير صحيحة');
        if (b.status === 'purchased' && !['purchasing', 'admin'].includes(user.role)) {
          return fail('تحديث المشتريات من قبل المشتريات فقط', 403);
        }
        if (b.status === 'completed' && !['warehouse', 'admin'].includes(user.role)) {
          return fail('تأكيد الاستلام من قبل المخزن فقط', 403);
        }
        transition = b.status;
        push('status', b.status);
        if (b.status === 'purchased') {
          push('purchased_by', user.id);
          push('purchased_at', now());
          if (b.quantity_purchased == null && num(current.quantity) > 0) push('quantity_purchased', num(current.quantity));
        }
        if (b.status === 'completed') {
          push('confirmed_by', user.id);
          push('completed_at', now());
          if (b.received_quantity == null) push('received_quantity', num(current.quantity_purchased) || num(current.quantity));
        }
        if (b.status === 'pending') {
          if (b.missing_reason != null) push('missing_reason', clampText(b.missing_reason, 300));
          push('purchased_by', null);
          push('purchased_at', null);
          push('completed_at', null);
          push('confirmed_by', null);
        }
      }

      if (!sets.length) return json({ ok: true, unchanged: true });
      vals.push(itemId);
      await env.DB.prepare(`UPDATE items SET ${sets.join(', ')} WHERE id=?`).bind(...vals).run();
      const updated = await env.DB.prepare('SELECT * FROM items WHERE id=?').bind(itemId).first();

      if (transition === 'purchased') {
        await notify(env, '🛒 تحديث المشتريات', `${current.name} — تم شراء الكمية المطلوبة`, 'warehouse');
      } else if (transition === 'completed') {
        await notify(env, '✅ تم استلام المادة', `${current.name} — دخلت المخزن`, 'purchasing');
      } else if (transition === 'pending') {
        await notify(env, 'إعادة طلب مادة! 🔄', `${current.name} — طلبت إعادة طلبها`, 'purchasing');
      }
      return json({ item: updated });
    }
  }

  if (pathname === '/api/notifications') {
    if (method === 'GET') {
      const { results } = await env.DB
        .prepare('SELECT * FROM notifications WHERE target_role=? OR target_role=? ORDER BY created_at DESC LIMIT 60')
        .bind(user.role, 'all')
        .all();
      return json({ notifications: results });
    }
    if (method === 'POST') {
      if (user.role !== 'admin') return fail('الإرسال للمدير فقط', 403);
      const b = await readJson(request);
      const title = clampText(b.title, 120);
      if (!title) return fail('العنوان مطلوب');
      const target = ROLES.includes(str(b.target_role)) ? str(b.target_role) : 'all';
      const created = { id: mkId('ntf'), title, body: clampText(b.body, 300), target_role: target, created_at: now() };
      await env.DB
        .prepare('INSERT INTO notifications (id,title,body,target_role,created_at) VALUES (?,?,?,?,?)')
        .bind(created.id, created.title, created.body, created.target_role, created.created_at)
        .run();
      return json({ notification: created }, 201);
    }
  }

  if (pathname === '/api/stats' && method === 'GET') {
    const { results } = await env.DB.prepare('SELECT status, COUNT(*) AS c FROM items GROUP BY status').all();
    const counts = { pending: 0, purchased: 0, completed: 0 };
    for (const r of results) counts[r.status] = r.c;
    return json({ counts });
  }

  return fail('المسار غير موجود', 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith('/api/')) return await handleApi(request, env, url);
      return await env.ASSETS.fetch(request);
    } catch (err) {
      return json({ error: 'خطأ داخلي بالخادم', detail: String(err?.message || err) }, 500);
    }
  }
};
