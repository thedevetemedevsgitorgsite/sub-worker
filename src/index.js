import { HttpError, json, ip, EMAIL, UUID, REF, toMinor, clean, randHex, body, db, rateLimit, audit,
  turnstile, authenticate, needMfa, idemKey, gotrue, sessionCookies, clearCookies } from './lib.js';
import { ps, initCheckout, paystackIp, verifySignature, sha256 } from './paystack.js';

const routes = [];
const route = (m, p, h, o = {}) => routes.push([m, new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), h, o]);

const effPlan = (p) => (p.plan !== 'free' && (!p.plan_expires_at || new Date(p.plan_expires_at) > new Date())) ? p.plan : 'free';
const firstName = (n) => { const p = String(n || '').split(' ').filter(Boolean); return p.length > 1 ? `${p[0]} ${p[p.length - 1][0]}.` : (p[0] || 'a SUB member'); };

/* ================= public config ================= */
route('GET', '/api/config', async ({ env }) => {
  const d = db(env);
  const [[fc], plans] = await Promise.all([d.get('sub_fee_config?select=*'), d.get('sub_plan_limits?select=*')]);
  return json({ fees: fc, plans, turnstileSiteKey: env.TURNSTILE_SITEKEY || '' });
}, { public: true });

/* ================= auth ================= */
route('POST', '/api/auth/signup', async ({ req, env }) => {
  const b = await body(req);
  await rateLimit(env, `signup:${ip(req)}`, 3600, 5);
  await turnstile(env, req, b.turnstile);
  const email = clean(b.email, 254).toLowerCase(), name = clean(b.name, 80);
  if (!EMAIL.test(email) || !name || String(b.password || '').length < 10 || String(b.password).length > 128)
    throw new HttpError(400, 'invalid_input', 'Check your details. Password needs 10+ characters.');
  await gotrue(env, '/signup', { method: 'POST', body: JSON.stringify({ email, password: b.password,
    data: { full_name: name } }) });
  // Same answer whether or not the email exists (no account enumeration).
  return json({ ok: true, message: 'Check your email to confirm your account, then log in.' });
}, { public: true });

route('POST', '/api/auth/login', async ({ req, env }) => {
  const b = await body(req);
  const email = clean(b.email, 254).toLowerCase();
  await rateLimit(env, `login:ip:${ip(req)}`, 900, 20);
  await rateLimit(env, `login:em:${email}`, 900, 8);
  await turnstile(env, req, b.turnstile);
  const r = await gotrue(env, '/token?grant_type=password', { method: 'POST',
    body: JSON.stringify({ email, password: String(b.password || '') }) });
  if (!r.ok) throw new HttpError(401, 'invalid_login', 'Invalid email or password');
  const t = await r.json();
  await audit(env, req, t.user?.id, 'login', null);
  return json({ ok: true }, 200, { 'set-cookie': sessionCookies(t) });
}, { public: true });

route('POST', '/api/auth/logout', async ({ req, env, auth }) => {
  await gotrue(env, '/logout', { method: 'POST', headers: { authorization: `Bearer ${auth.token}` } }).catch(() => {});
  await audit(env, req, auth.id, 'logout', null);
  return json({ ok: true }, 200, { 'set-cookie': clearCookies() });
});

/* ================= me ================= */
route('GET', '/api/me', async ({ env, auth }) => {
  const d = db(env), since = new Date(Date.now() - 864e5).toISOString();
  const [[p], [w], used] = await Promise.all([
    d.get(`sub_profiles?id=eq.${auth.id}&select=full_name,email,sub_tag,plan,plan_expires_at,card_frozen,is_admin,account_frozen`),
    d.get(`sub_wallets?user_id=eq.${auth.id}&select=balance,currency`),
    d.get(`sub_ledger_entries?user_id=eq.${auth.id}&kind=in.(sub_out,withdraw)&created_at=gte.${since}&select=delta`)]);
  const plan = effPlan(p);
  const [lim] = await d.get(`sub_plan_limits?plan=eq.${plan}&select=daily_out,fee_discount_bps`);
  const payouts = await d.get(`sub_payout_accounts?user_id=eq.${auth.id}&deleted_at=is.null&select=id`);
  return json({ name: p.full_name, email: p.email, tag: p.sub_tag, plan, planExpires: p.plan_expires_at,
    isPro: plan !== 'free', cardFrozen: p.card_frozen, frozen: p.account_frozen, isAdmin: p.is_admin,
    balance: w.balance, currency: w.currency, dailyLimit: lim.daily_out, discountBps: lim.fee_discount_bps,
    dailyUsed: used.reduce((s, r) => s - r.delta, 0), aal: auth.aal,
    mfaFactors: auth.factors.map(f => f.id), hasPayout: payouts.length > 0 });
});

route('POST', '/api/card', async ({ req, env, auth }) => {
  const b = await body(req);
  await db(env).patch(`sub_profiles?id=eq.${auth.id}`, { card_frozen: b.frozen === true });
  return json({ ok: true });
});

route('GET', '/api/history', async ({ env, auth, url }) => {
  const before = Number(url.searchParams.get('before')) || 0;
  const rows = await db(env).get(`sub_ledger_entries?user_id=eq.${auth.id}&select=id,kind,gross,fee,delta,ref,description,status,created_at`
    + `${before ? `&id=lt.${before}` : ''}&order=id.desc&limit=50`);
  const ids = rows.filter(r => r.kind === 'withdraw').map(r => r.ref.slice(3));
  if (ids.length) {
    const ws = await db(env).get(`sub_withdrawals?id=in.(${ids.filter(i => UUID.test(i)).join(',')})&select=id,status`);
    const m = Object.fromEntries(ws.map(w => [w.id, w.status]));
    rows.forEach(r => { if (r.kind === 'withdraw') r.status = m[r.ref.slice(3)] || r.status; });
  }
  return json({ items: rows });
});

/* ================= MFA (TOTP) ================= */
route('POST', '/api/mfa/enroll', async ({ env, auth }) => {
  const r = await gotrue(env, '/factors', { method: 'POST', headers: { authorization: `Bearer ${auth.token}` },
    body: JSON.stringify({ factor_type: 'totp', friendly_name: 'SUB-' + randHex(3) }) });
  if (!r.ok) throw new HttpError(400, 'mfa_enroll_failed');
  const f = await r.json();
  return json({ factorId: f.id, qr: f.totp.qr_code, secret: f.totp.secret });
});

route('POST', '/api/mfa/verify', async ({ req, env, auth }) => {
  const b = await body(req);
  await rateLimit(env, `mfa:${auth.id}`, 600, 10);
  if (!/^[0-9a-f-]{36}$/.test(b.factorId || '') || !/^\d{6}$/.test(b.code || '')) throw new HttpError(400, 'invalid_input');
  const H = { authorization: `Bearer ${auth.token}` };
  const c = await gotrue(env, `/factors/${b.factorId}/challenge`, { method: 'POST', headers: H });
  if (!c.ok) throw new HttpError(400, 'mfa_failed');
  const ch = await c.json();
  const v = await gotrue(env, `/factors/${b.factorId}/verify`, { method: 'POST', headers: H,
    body: JSON.stringify({ challenge_id: ch.id, code: b.code }) });
  if (!v.ok) throw new HttpError(401, 'mfa_failed', 'That code did not work');
  return json({ ok: true }, 200, { 'set-cookie': sessionCookies(await v.json()) });
});

/* ================= payment requests ================= */
route('POST', '/api/requests', async ({ req, env, auth }) => {
  const b = await body(req);
  await rateLimit(env, `mkreq:${auth.id}`, 3600, 30);
  const reason = clean(b.reason, 140);
  if (!reason) throw new HttpError(400, 'invalid_input', 'Add a reason');
  const ref = 'SUB-' + randHex(12).toUpperCase();
  const r = await db(env).rpc('create_payment_request', { p_owner: auth.id, p_amount: toMinor(b.amount),
    p_reason: reason, p_hint: clean(b.payerHint, 120), p_ref: ref });
  return json({ ref: r.ref, amount: r.amount, expiresAt: r.expires_at, link: `${env.APP_ORIGIN}/pages/pay.html?ref=${r.ref}` });
});

route('GET', '/api/requests', async ({ env, auth }) =>
  json({ items: await db(env).get(`sub_payment_requests?owner_id=eq.${auth.id}&select=ref,amount,reason,status,expires_at,created_at&order=created_at.desc&limit=50`) }));

route('POST', '/api/requests/:ref/cancel', async ({ env, auth, params }) => {
  if (!REF.test(params.ref)) throw new HttpError(404, 'not_found');
  await db(env).patch(`sub_payment_requests?ref=eq.${params.ref}&owner_id=eq.${auth.id}&status=eq.open`, { status: 'cancelled' });
  return json({ ok: true });
});

/* ---- public payer side: amount always comes from the DB, never the browser ---- */
async function loadOpenRequest(env, ref) {
  if (!REF.test(ref)) throw new HttpError(404, 'not_found');
  const [r] = await db(env).get(`sub_payment_requests?ref=eq.${ref}&select=id,ref,owner_id,amount,currency,reason,status,expires_at`);
  if (!r) throw new HttpError(404, 'not_found');
  if (r.status === 'open' && new Date(r.expires_at) < new Date()) r.status = 'expired';
  return r;
}

route('GET', '/api/public/requests/:ref', async ({ req, env, params }) => {
  await rateLimit(env, `pubget:${ip(req)}`, 60, 40);
  const r = await loadOpenRequest(env, params.ref);
  const [o] = await db(env).get(`sub_profiles?id=eq.${r.owner_id}&select=full_name`);
  return json({ amount: r.amount, currency: r.currency, reason: r.reason, status: r.status, to: firstName(o?.full_name) });
}, { public: true });

route('POST', '/api/public/requests/:ref/pay', async ({ req, env, params }) => {
  const b = await body(req);
  await rateLimit(env, `pubpay:${ip(req)}`, 600, 10);
  await rateLimit(env, `pubpayref:${params.ref}`, 3600, 20);
  await turnstile(env, req, b.turnstile);
  const email = clean(b.email, 254).toLowerCase(), name = clean(b.name, 80);
  if (!EMAIL.test(email) || !name) throw new HttpError(400, 'invalid_input', 'Enter your name and email');
  const r = await loadOpenRequest(env, params.ref);
  if (r.status !== 'open') throw new HttpError(409, 'not_payable', 'This link is no longer payable');
  const reference = r.ref.toLowerCase() + '-' + randHex(4);
  await db(env).insert('sub_payments', { reference, purpose: 'request', request_id: r.id, amount: r.amount,
    currency: r.currency, payer_email: email, payer_name: name });
  const url = await initCheckout(env, { email, amount: r.amount, currency: r.currency, reference,
    callback: `${env.APP_ORIGIN}/pages/pay.html?ref=${r.ref}&done=1`, metadata: { purpose: 'request', ref: r.ref } });
  return json({ url });
}, { public: true });

/* ================= SUB-to-SUB ================= */
async function findRecipient(env, raw) {
  const v = clean(raw, 254).toLowerCase();
  let q;
  if (v.startsWith('@') && /^[a-f0-9]{8}$/.test(v.slice(1))) q = `sub_tag=eq.${v.slice(1)}`;
  else if (EMAIL.test(v)) q = `email=eq.${encodeURIComponent(v)}`;
  else throw new HttpError(404, 'recipient_not_found', 'Recipient not found');
  const [p] = await db(env).get(`sub_profiles?${q}&select=id,full_name,sub_tag`);
  if (!p) throw new HttpError(404, 'recipient_not_found', 'Recipient not found');
  return p;
}

route('POST', '/api/transfers/lookup', async ({ req, env, auth }) => {
  await rateLimit(env, `lookup:${auth.id}`, 600, 20);
  const p = await findRecipient(env, (await body(req)).recipient);
  return json({ name: firstName(p.full_name), tag: p.sub_tag });
});

route('POST', '/api/transfers', async ({ req, env, auth }) => {
  const b = await body(req), key = idemKey(req), amount = toMinor(b.amount);
  await rateLimit(env, `xfer:${auth.id}`, 3600, 30);
  if (amount >= Number(env.MFA_TRANSFER_MIN || 5000000)) needMfa(auth);
  const p = await findRecipient(env, b.recipient);
  const e = await db(env).rpc('transfer_sub', { p_sender: auth.id, p_recipient: p.id, p_amount: amount,
    p_note: clean(b.note, 80), p_idem: key });
  await audit(env, req, auth.id, 'transfer', p.id, { amount });
  return json({ ok: true, balanceAfter: e.balance_after });
});

/* ================= payout accounts + withdrawals ================= */
route('GET', '/api/banks', async ({ env }) => {
  const cache = caches.default, ckey = new Request('https://cache.local/banks/' + env.PAYSTACK_COUNTRY);
  let hit = await cache.match(ckey);
  if (hit) return hit;
  const r = await ps(env, `/bank?country=${encodeURIComponent(env.PAYSTACK_COUNTRY || 'nigeria')}&perPage=200`);
  if (!r.ok) throw new HttpError(502, 'banks_unavailable');
  const res = json({ items: r.data.map(b => ({ name: b.name, code: b.code })) }, 200, { 'cache-control': 'public, max-age=86400' });
  await cache.put(ckey, res.clone());
  return res;
});

route('GET', '/api/payout-accounts', async ({ env, auth }) =>
  json({ items: await db(env).get(`sub_payout_accounts?user_id=eq.${auth.id}&deleted_at=is.null&select=id,bank_name,account_last4,account_name,is_default,usable_after&order=created_at`) }));

route('POST', '/api/payout-accounts', async ({ req, env, auth }) => {
  needMfa(auth);
  const b = await body(req);
  await rateLimit(env, `addbank:${auth.id}`, 3600, 5);
  if (!/^[0-9A-Za-z-]{2,12}$/.test(b.bankCode || '') || !/^\d{6,20}$/.test(b.accountNumber || ''))
    throw new HttpError(400, 'invalid_input', 'Check the bank and account number');
  const r = await ps(env, `/bank/resolve?account_number=${b.accountNumber}&bank_code=${encodeURIComponent(b.bankCode)}`);
  if (!r.ok) throw new HttpError(422, 'account_not_found', 'Could not verify that account');
  const rec = await ps(env, '/transferrecipient', { method: 'POST', body: { type: 'nuban', name: r.data.account_name,
    account_number: b.accountNumber, bank_code: b.bankCode, currency: env.PAYOUT_CURRENCY || 'NGN' } });
  if (!rec.ok) throw new HttpError(502, 'recipient_failed');
  const existing = await db(env).get(`sub_payout_accounts?user_id=eq.${auth.id}&deleted_at=is.null&select=id`);
  const hours = Number(env.NEW_PAYOUT_COOLDOWN_HOURS ?? 24);
  const [row] = await db(env).insert('sub_payout_accounts', { user_id: auth.id, bank_code: b.bankCode,
    bank_name: rec.data.details?.bank_name || 'Bank', account_last4: b.accountNumber.slice(-4),
    account_name: r.data.account_name, recipient_code: rec.data.recipient_code,
    is_default: existing.length === 0, usable_after: new Date(Date.now() + hours * 36e5).toISOString() });
  await audit(env, req, auth.id, 'payout_add', row.id);
  return json({ id: row.id, usableAfter: row.usable_after });
});

route('DELETE', '/api/payout-accounts/:id', async ({ req, env, auth, params }) => {
  needMfa(auth);
  if (!UUID.test(params.id)) throw new HttpError(404, 'not_found');
  await db(env).patch(`sub_payout_accounts?id=eq.${params.id}&user_id=eq.${auth.id}`, { deleted_at: new Date().toISOString() });
  await audit(env, req, auth.id, 'payout_remove', params.id);
  return json({ ok: true });
});

route('POST', '/api/withdrawals', async ({ req, env, auth }) => {
  needMfa(auth);
  const b = await body(req), key = idemKey(req);
  await rateLimit(env, `wd:${auth.id}`, 3600, 5);
  if (!UUID.test(b.payoutId || '')) throw new HttpError(400, 'invalid_input');
  const w = await db(env).rpc('request_withdrawal', { p_user: auth.id, p_amount: toMinor(b.amount), p_payout: b.payoutId, p_idem: key });
  await audit(env, req, auth.id, 'withdraw_request', w.id, { amount: w.amount });
  return json({ id: w.id, status: w.status, fee: w.fee });
});

route('GET', '/api/withdrawals', async ({ env, auth }) =>
  json({ items: await db(env).get(`sub_withdrawals?user_id=eq.${auth.id}&select=id,amount,fee,status,created_at,sub_payout_accounts(bank_name,account_last4)&order=created_at.desc&limit=50`) }));

/* ================= plans ================= */
route('POST', '/api/plan/checkout', async ({ env, auth, req }) => {
  const b = await body(req);
  if (!['plus', 'platinum'].includes(b.plan)) throw new HttpError(400, 'invalid_input');
  await rateLimit(env, `plan:${auth.id}`, 3600, 10);
  const [pl] = await db(env).get(`sub_plan_limits?plan=eq.${b.plan}&select=price`);
  const [fc] = await db(env).get('sub_fee_config?select=currency');
  const reference = 'pln-' + randHex(10);
  await db(env).insert('sub_payments', { reference, purpose: 'plan', user_id: auth.id, plan: b.plan, amount: pl.price,
    currency: fc.currency, payer_email: auth.user.email });
  const url = await initCheckout(env, { email: auth.user.email, amount: pl.price, currency: fc.currency, reference,
    callback: `${env.APP_ORIGIN}/pages/pro.html?done=1`, metadata: { purpose: 'plan', plan: b.plan } });
  return json({ url });
});

/* ================= Paystack webhook ================= */
async function applyTransfer(env, id, status) {
  const d = db(env);
  if (status === 'success') return d.rpc('mark_withdrawal_paid', { p_id: id });
  if (status === 'failed') return d.rpc('fail_withdrawal', { p_id: id, p_new_status: 'failed', p_note: 'transfer failed' });
  if (status === 'reversed') return d.rpc('fail_withdrawal', { p_id: id, p_new_status: 'reversed', p_note: 'transfer reversed' });
  return 'no_change';
}

route('POST', '/api/webhooks/paystack', async ({ req, env }) => {
  if (env.PAYSTACK_IP_CHECK === 'true' && !paystackIp(ip(req))) throw new HttpError(403, 'forbidden');
  if (Number(req.headers.get('content-length') || 0) > 65536) throw new HttpError(413, 'too_large');
  const raw = await req.text();
  if (!(await verifySignature(env, raw, req.headers.get('x-paystack-signature')))) throw new HttpError(401, 'bad_signature');
  const ev = JSON.parse(raw), ref = ev.data?.reference;
  if (!ref) return json({ ok: true });
  await db(env).insert('sub_webhook_events', { event_key: `${ev.event}:${ref}`, payload_sha256: await sha256(raw) }, { ignoreDup: true });

  // Never trust the payload alone: re-ask Paystack, then run idempotent SQL.
  if (ev.event === 'charge.success') {
    const v = await ps(env, `/transaction/verify/${encodeURIComponent(ref)}`);
    if (!v.ok) throw new HttpError(502, 'verify_failed');            // 5xx makes Paystack retry
    if (v.data.status !== 'success') return json({ ok: true });
    const res = await db(env).rpc('settle_payment', { p_reference: ref, p_paid: v.data.amount, p_currency: v.data.currency });
    console.log('settle', ref, res);
  } else if (/^transfer\.(success|failed|reversed)$/.test(ev.event) && /^wd-/.test(ref)) {
    const id = ref.slice(3);
    if (!UUID.test(id)) return json({ ok: true });
    const v = await ps(env, `/transfer/verify/${encodeURIComponent(ref)}`);
    if (!v.ok) throw new HttpError(502, 'verify_failed');
    await applyTransfer(env, id, v.data.status);
  }
  return json({ ok: true });
}, { public: true, webhook: true });

/* ================= admin ================= */
async function admin(ctx) {
  const { env, auth, req } = ctx;
  const [p] = await db(env).get(`sub_profiles?id=eq.${auth.id}&select=is_admin`);
  if (!p?.is_admin) throw new HttpError(404, 'not_found');
  if (env.ADMIN_IPS && !env.ADMIN_IPS.split(',').map(s => s.trim()).includes(ip(req))) throw new HttpError(404, 'not_found');
  needMfa(auth);
}

route('GET', '/api/admin/withdrawals', async (ctx) => {
  await admin(ctx);
  const st = ctx.url.searchParams.get('status') || 'pending_review';
  if (!/^[a-z_]+$/.test(st)) throw new HttpError(400, 'invalid_input');
  return json({ items: await db(ctx.env).get(`sub_withdrawals?status=eq.${st}&select=id,user_id,amount,fee,currency,status,created_at,sub_payout_accounts(bank_name,account_last4,account_name),sub_profiles!sub_withdrawals_user_id_fkey(email,full_name)&order=created_at&limit=100`) });
});

route('POST', '/api/admin/withdrawals/:id/approve', async (ctx) => {
  await admin(ctx);
  const { env, auth, req, params } = ctx;
  if (!UUID.test(params.id)) throw new HttpError(404, 'not_found');
  const w = await db(env).rpc('admin_claim_withdrawal', { p_id: params.id, p_admin: auth.id });
  await audit(env, req, auth.id, 'wd_approve', w.id);
  const [pay] = await db(env).get(`sub_payout_accounts?id=eq.${w.payout_id}&select=recipient_code`);
  const r = await ps(env, '/transfer', { method: 'POST', body: { source: 'balance', amount: w.amount - w.fee,
    recipient: pay.recipient_code, reference: 'wd-' + w.id, reason: 'SUB withdrawal', currency: w.currency } });
  if (r.ok) return json({ status: r.data.status });                 // success | pending | otp
  if (/balance/i.test(r.message)) {                                  // top up Paystack, then approve again
    await db(env).rpc('admin_release_withdrawal', { p_id: w.id });
    throw new HttpError(409, 'paystack_balance_low', 'Paystack balance too low. Withdrawal returned to the queue.');
  }
  if (r.status >= 400 && r.status < 500 && r.status !== 429 && !/reference/i.test(r.message)) {
    await db(env).rpc('fail_withdrawal', { p_id: w.id, p_new_status: 'failed', p_note: r.message.slice(0, 200) });
    throw new HttpError(422, 'transfer_rejected', 'Paystack refused the transfer. User was refunded.');
  }
  return json({ status: 'unknown', hint: 'Use Sync to confirm with Paystack' }, 202);
});

route('POST', '/api/admin/withdrawals/:id/sync', async (ctx) => {
  await admin(ctx);
  const { env, params } = ctx;
  if (!UUID.test(params.id)) throw new HttpError(404, 'not_found');
  const v = await ps(env, `/transfer/verify/wd-${params.id}`);
  if (v.status === 404) return json({ result: await db(env).rpc('admin_release_withdrawal', { p_id: params.id }) });
  if (!v.ok) throw new HttpError(502, 'verify_failed');
  return json({ paystack: v.data.status, result: await applyTransfer(env, params.id, v.data.status) });
});

route('POST', '/api/admin/withdrawals/:id/reject', async (ctx) => {
  await admin(ctx);
  const { env, auth, req, params } = ctx;
  if (!UUID.test(params.id)) throw new HttpError(404, 'not_found');
  const b = await body(req);
  const res = await db(env).rpc('fail_withdrawal', { p_id: params.id, p_new_status: 'rejected', p_note: clean(b.note, 200) });
  await audit(env, req, auth.id, 'wd_reject', params.id);
  return json({ result: res });
});

route('GET', '/api/admin/integrity', async (ctx) => {
  await admin(ctx);
  const d = db(ctx.env);
  return json({ mismatched: await d.get('integrity_check?select=*'),
    needsReview: await d.get('sub_payments?status=eq.needs_review&select=reference,amount,payer_email,created_at') });
});

/* ================= entry ================= */
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    try {
      const hit = routes.find(([m, re]) => m === req.method && re.test(url.pathname));
      if (!hit) throw new HttpError(404, 'not_found');
      const [, re, handler, opts] = hit;
      if (req.method !== 'GET' && !opts.webhook && req.headers.get('origin') !== env.APP_ORIGIN)
        throw new HttpError(403, 'bad_origin');
      const ctx = { req, env, url, params: url.pathname.match(re).groups || {}, auth: null };
      if (!opts.public) ctx.auth = await authenticate(req, env);
      const res = await handler(ctx);
      if (ctx.auth?.cookies.length) ctx.auth.cookies.forEach(c => res.headers.append('set-cookie', c));
      return res;
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.code, message: e.message }, e.status);
      console.error('unhandled', e?.stack || e);
      return json({ error: 'server_error' }, 500);
    }
  },
};
