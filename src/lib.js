export class HttpError extends Error {
  constructor(status, code, message) { super(message || code); this.status = status; this.code = code; }
}
export const json = (data, status = 200, headers = {}) => {
  const h = new Headers({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
    'x-content-type-options': 'nosniff' });
  for (const [k, v] of Object.entries(headers)) (Array.isArray(v) ? v : [v]).forEach(x => h.append(k, x));
  return new Response(JSON.stringify(data), { status, headers: h });
};

export const ip = (req) => req.headers.get('CF-Connecting-IP') || '0.0.0.0';
export const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const REF = /^SUB-[0-9A-F]{24}$/;

export function toMinor(v) {
  const s = String(v ?? '').trim();
  if (!/^\d{1,10}(\.\d{1,2})?$/.test(s)) throw new HttpError(400, 'bad_amount', 'Invalid amount');
  const [a, b = ''] = s.split('.');
  return Number(a) * 100 + Number((b + '00').slice(0, 2));
}
export const clean = (s, max) => String(s ?? '').replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, max);
export const randHex = (bytes) => [...crypto.getRandomValues(new Uint8Array(bytes))]
  .map(b => b.toString(16).padStart(2, '0')).join('');

export async function body(req, max = 8192) {
  const len = Number(req.headers.get('content-length') || 0);
  if (len > max) throw new HttpError(413, 'too_large');
  try { return JSON.parse(await req.text() || '{}'); } catch { throw new HttpError(400, 'bad_json'); }
}

/* ---------- Supabase (service role, server side only) ---------- */
const KNOWN = new Set(['insufficient_funds', 'daily_limit', 'amount_too_small', 'account_frozen',
  'self_transfer', 'payout_not_found', 'payout_cooldown', 'bad_state', 'self_approval', 'not_found']);

export function db(env) {
  const h = { apikey: env.SUPABASE_SERVICE_KEY, authorization: `Bearer ${env.SUPABASE_SERVICE_KEY}`,
    'content-type': 'application/json' };
  const fail = async (r) => {
    const e = await r.json().catch(() => ({}));
    const m = String(e.message || '');
    if (KNOWN.has(m)) throw new HttpError(m === 'not_found' ? 404 : 409, m);
    console.error('db error', r.status, m.slice(0, 200));
    throw new HttpError(500, 'server_error');
  };
  return {
    async rpc(fn, args) {
      const r = await fetch(`${env.SUPABASE_URL}/rest/v1/rpc/${fn}`, { method: 'POST', headers: h, body: JSON.stringify(args) });
      if (!r.ok) await fail(r);
      return r.json();
    },
    async get(path) {
      const r = await fetch(`${env.SUPABASE_URL}/rest/v1/${path}`, { headers: h });
      if (!r.ok) await fail(r);
      return r.json();
    },
    async insert(table, row, { ignoreDup = false } = {}) {
      const r = await fetch(`${env.SUPABASE_URL}/rest/v1/${table}`, { method: 'POST',
        headers: { ...h, prefer: `return=representation${ignoreDup ? ',resolution=ignore-duplicates' : ''}` },
        body: JSON.stringify(row) });
      if (!r.ok) await fail(r);
      return r.json();
    },
    async patch(path, row) {
      const r = await fetch(`${env.SUPABASE_URL}/rest/v1/${path}`, { method: 'PATCH',
        headers: { ...h, prefer: 'return=representation' }, body: JSON.stringify(row) });
      if (!r.ok) await fail(r);
      return r.json();
    },
  };
}

export async function rateLimit(env, key, windowS, max) {
  let ok;
  try { ok = await db(env).rpc('rl_hit', { p_key: key, p_window_s: windowS, p_max: max }); }
  catch { throw new HttpError(503, 'unavailable'); }          // fail closed
  if (!ok) throw new HttpError(429, 'rate_limited', 'Too many attempts. Try again later.');
}

export async function audit(env, req, actor, action, target, meta) {
  try {
    await db(env).insert('sub_audit_log', { actor, action, target: target ? String(target) : null,
      ip: ip(req), ua: (req.headers.get('user-agent') || '').slice(0, 200), meta: meta || null });
  } catch (e) { console.error('audit failed', action); }
}

export async function turnstile(env, req, token) {
  if (env.TURNSTILE_DISABLED === 'true') return;
  if (!env.TURNSTILE_SECRET || !token) throw new HttpError(400, 'captcha_required');
  const f = new FormData();
  f.set('secret', env.TURNSTILE_SECRET); f.set('response', String(token).slice(0, 2048)); f.set('remoteip', ip(req));
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: f });
  const d = await r.json().catch(() => ({}));
  if (!d.success) throw new HttpError(400, 'captcha_failed');
}

/* ---------- Auth: HttpOnly cookies, tokens never touch JS ---------- */
const AT = '__Secure-sub_at', RT = '__Secure-sub_rt';
const ck = (n, v, age) => `${n}=${v}; Max-Age=${age}; Path=/api; HttpOnly; Secure; SameSite=Strict`;
export const sessionCookies = (t) => [ck(AT, t.access_token, Math.max(60, t.expires_in || 3600)),
  ck(RT, t.refresh_token, 60 * 60 * 24 * 30)];
export const clearCookies = () => [ck(AT, '', 0), ck(RT, '', 0)];
const parseCookies = (req) => Object.fromEntries((req.headers.get('cookie') || '').split(';')
  .map(c => c.trim().split('=')).filter(p => p[0]).map(([k, ...v]) => [k, v.join('=')]));

const gotrue = (env, path, opts = {}) => fetch(`${env.SUPABASE_URL}/auth/v1${path}`, { ...opts,
  headers: { apikey: env.SUPABASE_ANON_KEY, 'content-type': 'application/json', ...(opts.headers || {}) } });
export { gotrue };

function jwtPayload(t) {
  try { return JSON.parse(atob(t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))); } catch { return {}; }
}

export async function authenticate(req, env) {
  const c = parseCookies(req);
  let at = c[AT], user = null, cookies = [];
  const lookup = async (t) => {
    const r = await gotrue(env, '/user', { headers: { authorization: `Bearer ${t}` } });
    return r.ok ? r.json() : null;
  };
  if (at) user = await lookup(at);
  if (!user && c[RT]) {
    const r = await gotrue(env, '/token?grant_type=refresh_token', { method: 'POST',
      body: JSON.stringify({ refresh_token: c[RT] }) });
    if (r.ok) { const t = await r.json(); at = t.access_token; user = await lookup(at); cookies = sessionCookies(t); }
  }
  if (!user || !user.email_confirmed_at) throw new HttpError(401, 'unauthenticated');
  return { user, id: user.id, token: at, aal: jwtPayload(at).aal || 'aal1', cookies,
    factors: (user.factors || []).filter(f => f.status === 'verified' && f.factor_type === 'totp') };
}

export function needMfa(a) {
  if (a.aal === 'aal2') return;
  if (!a.factors.length) throw new HttpError(403, 'mfa_enroll_required', 'Turn on two-step login in Settings first');
  throw new HttpError(403, 'mfa_required', 'Enter your authenticator code');
}

export const idemKey = (req) => {
  const k = req.headers.get('idempotency-key') || '';
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(k)) throw new HttpError(400, 'idempotency_key_required');
  return k;
};
