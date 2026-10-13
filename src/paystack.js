import { HttpError } from './lib.js';

export async function ps(env, path, { method = 'GET', body } = {}) {
  const r = await fetch('https://api.paystack.co' + path, { method, signal: AbortSignal.timeout(15000),
    headers: { authorization: `Bearer ${env.PAYSTACK_SECRET_KEY}`, 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined }).catch(() => null);
  if (!r) return { ok: false, status: 0, message: 'network' };
  const d = await r.json().catch(() => null);
  return { ok: r.ok && d?.status === true, status: r.status, data: d?.data, message: d?.message || '' };
}

export async function initCheckout(env, { email, amount, currency, reference, callback, metadata }) {
  const r = await ps(env, '/transaction/initialize', { method: 'POST',
    body: { email, amount, currency, reference, callback_url: callback, metadata } });
  if (!r.ok) { console.error('paystack init', r.status, r.message); throw new HttpError(502, 'payment_unavailable'); }
  return r.data.authorization_url;
}

const PAYSTACK_IPS = ['52.31.139.75', '52.49.173.169', '52.214.14.220'];   // verify against Paystack docs
export const paystackIp = (ip) => PAYSTACK_IPS.includes(ip);

export async function verifySignature(env, raw, sigHex) {
  if (!/^[0-9a-f]{128}$/i.test(sigHex || '')) return false;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.PAYSTACK_SECRET_KEY),
    { name: 'HMAC', hash: 'SHA-512' }, false, ['verify']);
  const sig = Uint8Array.from(sigHex.match(/../g).map(h => parseInt(h, 16)));
  return crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(raw));   // constant time
}

export const sha256 = async (s) => [...new Uint8Array(await crypto.subtle.digest('SHA-256',
  new TextEncoder().encode(s)))].map(b => b.toString(16).padStart(2, '0')).join('');
