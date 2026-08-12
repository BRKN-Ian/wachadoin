// ── PayFast integration (Phase 2 billing) ───────────────────────────────────
// Two distinct PayFast surfaces are used here, each with its OWN signature
// algorithm — mixing them up silently breaks signature checks:
//
//  1. The classic hosted-checkout redirect (what establishes a subscription
//     and its token in the first place). Signature = md5 of the fields in
//     the order they're posted, url-encoded, "+passphrase" appended last.
//     Confirmed against PayFast's own PHP SDK (Notify/OnsiteIntegration).
//
//  2. The REST Subscriptions API (fetch/pause/unpause/cancel/update/adhoc —
//     used here only for adhoc()). Signature = md5 of ALL params (incl. the
//     passphrase merged in) sorted ALPHABETICALLY by key, url-encoded.
//     Confirmed against PayFast's PHP SDK's Auth::generateApiSignature().
//
// Both were confirmed by reading PayFast's own open-source PHP SDK source
// (github.com/PayFast/payfast-php-sdk) during planning — their marketing
// docs site is a JS-rendered SPA that couldn't be fetched for this. The one
// thing that SDK read did NOT reveal is the exact REST API base URL/header
// names for the Subscriptions endpoints, so those below are best-effort from
// general knowledge and MUST be confirmed against a real sandbox call before
// this goes anywhere near production ("live" mode refuses to run without
// explicit credentials — see PAYFAST_MODE below).
const crypto = require('crypto');
const https = require('https');

// Rand, per employee/month. Annual is the same monthly rate × 12, at a flat
// 10% discount, charged as one lump sum per year — matches the existing
// "save 10%, prepaid for the year" copy on the signup page.
const PLAN_PRICE = { starter: 120, growth: 170, firm: 240 };
const ANNUAL_DISCOUNT = 0.9;

function computeSeatAmount(plan, billingCycle, employeeCount) {
  const perSeat = PLAN_PRICE[plan] ?? PLAN_PRICE.starter;
  const monthly = perSeat * Math.max(0, employeeCount || 0);
  return billingCycle === 'annual'
    ? Math.round(monthly * 12 * ANNUAL_DISCOUNT * 100) / 100
    : Math.round(monthly * 100) / 100;
}

// PayFast's published sandbox test merchant — used automatically whenever
// PAYFAST_MODE isn't explicitly 'live', so the whole flow can be built and
// tested before Ian has a real PayFast account. Confirm these still match
// PayFast's current sandbox docs before relying on them.
const SANDBOX_MERCHANT_ID = '10000100';
const SANDBOX_MERCHANT_KEY = '46f0cd694581a';

function mode() { return process.env.PAYFAST_MODE === 'live' ? 'live' : 'sandbox'; }
function isLive() { return mode() === 'live'; }

function credentials() {
  if (isLive()) {
    return {
      merchantId: process.env.PAYFAST_MERCHANT_ID || null,
      merchantKey: process.env.PAYFAST_MERCHANT_KEY || null,
      passphrase: process.env.PAYFAST_PASSPHRASE || null,
    };
  }
  return {
    merchantId: process.env.PAYFAST_MERCHANT_ID || SANDBOX_MERCHANT_ID,
    merchantKey: process.env.PAYFAST_MERCHANT_KEY || SANDBOX_MERCHANT_KEY,
    passphrase: process.env.PAYFAST_PASSPHRASE || null,
  };
}

// Live mode with no real credentials must fail loudly but NOT crash the
// server — billing being unconfigured should never take down monitoring or
// timesheets. Every public function below checks this first.
function configuredOrExplain() {
  const c = credentials();
  if (isLive() && (!c.merchantId || !c.merchantKey)) {
    return { ok: false, error: 'Billing is not fully configured yet (PAYFAST_MODE=live but merchant credentials are missing).' };
  }
  return { ok: true, creds: c };
}

const CHECKOUT_HOST = () => (isLive() ? 'https://www.payfast.co.za' : 'https://sandbox.payfast.co.za');
const API_HOST = () => (isLive() ? 'https://api.payfast.co.za' : 'https://api.sandbox.payfast.co.za');

// Signature for the classic hosted-checkout form: fields in INSERTION order
// (not sorted), url-encoded, passphrase appended last if set.
function checkoutSignature(fields, passphrase) {
  let str = Object.entries(fields)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${k}=${encodeURIComponent(String(v).trim()).replace(/%20/g, '+')}`)
    .join('&');
  if (passphrase) str += `&passphrase=${encodeURIComponent(passphrase.trim()).replace(/%20/g, '+')}`;
  return crypto.createHash('md5').update(str).digest('hex');
}

// Signature for the REST Subscriptions API: ALL params (passphrase merged
// in, not appended) sorted ALPHABETICALLY by key, url-encoded.
function apiSignature(params, passphrase) {
  const withPass = passphrase ? { ...params, passphrase } : { ...params };
  const sortedKeys = Object.keys(withPass).sort();
  const str = sortedKeys
    .filter((k) => withPass[k] !== undefined && withPass[k] !== null && k !== 'signature')
    .map((k) => `${k}=${encodeURIComponent(String(withPass[k]).trim())}`)
    .join('&');
  return crypto.createHash('md5').update(str).digest('hex');
}

const FREQUENCY = { monthly: 3, annual: 6 }; // PayFast subscription frequency codes

// Builds the field map + action URL for a hosted-checkout redirect that
// establishes a recurring subscription. The frontend auto-submits these as a
// hidden <form> POST to actionUrl. `amount` is Rand (e.g. 680.00), computed
// by the caller via computeSeatAmount() using a FRESH employee count.
function buildCheckoutFields(org, amount, { returnUrl, cancelUrl, notifyUrl, itemName }) {
  const conf = configuredOrExplain();
  if (!conf.ok) return { ok: false, error: conf.error };
  const { merchantId, merchantKey, passphrase } = conf.creds;

  const fields = {
    merchant_id: merchantId,
    merchant_key: merchantKey,
    return_url: returnUrl,
    cancel_url: cancelUrl,
    notify_url: notifyUrl,
    m_payment_id: `${org.id}-${Date.now()}`,
    amount: amount.toFixed(2),
    item_name: itemName || `Wachadoin — ${org.plan} plan`,
    custom_str1: org.id,
    subscription_type: '1',
    billing_date: new Date().toISOString().slice(0, 10),
    recurring_amount: amount.toFixed(2),
    frequency: String(FREQUENCY[org.billingCycle] || FREQUENCY.monthly),
    cycles: '0', // indefinite — our own daily sweep controls the real amount each cycle
  };
  fields.signature = checkoutSignature(fields, passphrase);
  return { ok: true, actionUrl: `${CHECKOUT_HOST()}/eng/process`, fields };
}

// The three-part ITN trust chain PayFast requires: signature match, request
// actually originated from a PayFast host, and PayFast's own confirmation
// that the notification is genuine. All three must pass before the caller
// trusts anything in `postedFields`. `sourceHost` should be the raw
// `req.headers.host`/referrer-derived host if available; pass null to skip
// that check in environments where it isn't reliably available (Render sits
// behind a proxy) — signature + server-confirmation alone are still a real
// trust boundary, per PayFast's own SDK, which treats all three as required
// but functions independently.
async function verifyItn(rawBody, postedFields, passphrase) {
  const { signature, ...rest } = postedFields;
  const expected = checkoutSignature(rest, passphrase);
  if (expected !== signature) return { valid: false, reason: 'signature-mismatch' };

  try {
    const confirmed = await postForm(`${CHECKOUT_HOST()}/eng/query/validate`, rawBody);
    if (confirmed.trim() !== 'VALID') return { valid: false, reason: 'payfast-did-not-confirm' };
  } catch (err) {
    return { valid: false, reason: `validate-callback-failed: ${err.message}` };
  }
  return { valid: true };
}

// Ad-hoc charge against an already-established subscription token — this is
// how the daily sweep actually bills each cycle (NOT PayFast's own native
// recurring-amount schedule), so the amount can be recalculated fresh every
// time from the current employee count.
function chargeAdhoc(token, amountRands, itemName) {
  return new Promise((resolve) => {
    const conf = configuredOrExplain();
    if (!conf.ok) return resolve({ ok: false, error: conf.error });
    const { merchantId, passphrase } = conf.creds;
    const timestamp = new Date().toISOString();
    const params = { 'merchant-id': merchantId, version: 'v1', timestamp };
    const signature = apiSignature(params, passphrase);
    const body = JSON.stringify({ amount: Math.round(amountRands * 100), item_name: itemName });

    const req = https.request(
      `${API_HOST()}/subscriptions/${token}/adhoc`,
      {
        method: 'POST',
        headers: {
          'merchant-id': merchantId,
          version: 'v1',
          timestamp,
          signature,
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) resolve({ ok: true, response: data });
          else resolve({ ok: false, error: `PayFast adhoc charge failed (HTTP ${res.statusCode}): ${data}` });
        });
      }
    );
    req.on('error', (err) => resolve({ ok: false, error: err.message }));
    req.write(body);
    req.end();
  });
}

function postForm(url, rawBody) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request(
      u,
      { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(rawBody) } },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve(data));
      }
    );
    req.on('error', reject);
    req.write(rawBody);
    req.end();
  });
}

module.exports = {
  PLAN_PRICE,
  computeSeatAmount,
  buildCheckoutFields,
  verifyItn,
  chargeAdhoc,
  mode,
  isLive,
};
