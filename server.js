'use strict';
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { MongoClient } = require('mongodb');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '4mb' }));
app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

/* ---------- config ---------- */
const DB_NAME = process.env.MONGODB_DB || 'gmartt';
const SECRET = process.env.TOKEN_SECRET || process.env.MONGODB_URI || 'dev-only-secret';
const TOKEN_TTL = 12 * 3600 * 1000;

/* ---------- mongo (cached across serverless invocations) ---------- */
let clientPromise = null;
function getDb() {
  if (!process.env.MONGODB_URI) return Promise.reject(Object.assign(new Error('Database not configured (MONGODB_URI missing)'), { status: 500 }));
  if (!clientPromise) {
    clientPromise = new MongoClient(process.env.MONGODB_URI, { maxPoolSize: 5 }).connect()
      .catch(e => { clientPromise = null; throw e; });
  }
  return clientPromise.then(c => c.db(DB_NAME));
}

/* ---------- validation ---------- */
const str = (v, n = 500) => String(v ?? '').trim().slice(0, n);
const img = v => { v = String(v ?? ''); return /^(https?:\/\/|data:image\/)/i.test(v) && v.length < 3000000 ? v : ''; };
const SCHEMA = {
  categories: b => ({ name: str(b.name, 60), icon: img(b.icon) }),
  accounts: b => ({
    game: str(b.game, 60), title: str(b.title, 120),
    level: Math.max(0, parseInt(b.level) || 0), price: Math.max(0, Number(b.price) || 0),
    status: b.status === 'Sold' ? 'Sold' : 'Available', desc: str(b.desc, 1000),
    images: (Array.isArray(b.images) ? b.images : []).slice(0, 10).map(img).filter(Boolean)
  }),
  banners: b => ({ image: img(b.image) }),
  services: b => ({ title: str(b.title, 80), desc: str(b.desc, 200), link: /^https?:\/\//i.test(b.link || '') ? str(b.link, 300) : '#', image: img(b.image) })
};
const REQUIRED = { categories: 'name', accounts: 'title', banners: 'image', services: 'title' };
const SETTING_KEYS = ['site_logo', 'khqr_image'];
const validId = id => /^[\w-]{1,64}$/.test(String(id));

/* ---------- auth ---------- */
const sign = p => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
const makeToken = () => { const p = Buffer.from(JSON.stringify({ exp: Date.now() + TOKEN_TTL })).toString('base64url'); return p + '.' + sign(p); };
function verifyToken(t) {
  const [p, s] = String(t || '').split('.');
  if (!p || !s) return false;
  const e = sign(p);
  if (s.length !== e.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e))) return false;
  try { return JSON.parse(Buffer.from(p, 'base64url').toString()).exp > Date.now(); } catch { return false; }
}
const auth = (req, res, next) =>
  verifyToken((req.headers.authorization || '').replace(/^Bearer /, '')) ? next() : res.status(401).json({ error: 'Session expired. Please log in again.' });

const hashPw = (pw, salt = crypto.randomBytes(16).toString('hex')) => salt + ':' + crypto.scryptSync(pw, salt, 32).toString('hex');
const checkPw = (pw, stored) => { const [salt, h] = stored.split(':'); const c = hashPw(pw, salt).split(':')[1]; return crypto.timingSafeEqual(Buffer.from(c), Buffer.from(h)); };
const sha = s => crypto.createHash('sha256').update(String(s)).digest();

const attempts = new Map();
const tooMany = ip => { const n = Date.now(); const a = (attempts.get(ip) || []).filter(t => n - t < 15 * 60000); attempts.set(ip, a); return a.length >= 10; };

/* ---------- seed defaults (once) ---------- */
const PH = (w, h, c, t) => `https://placehold.co/${w}x${h}/0f172a/${c}?text=${t}`;
let seeding = null;
function ensureSeed() {
  if (!seeding) seeding = (async () => {
    const d = await getDb();
    if (await d.collection('settings').findOne({ _id: 'seeded' })) return;
    const t = Date.now();
    const ins = (name, rows) => rows.length ? d.collection(name).insertMany(rows.map((r, i) => ({ _id: r.id, ts: t + i, ...Object.fromEntries(Object.entries(r).filter(([k]) => k !== 'id')) }))) : null;
    await ins('categories', [
      { id: '1', name: 'Free Fire', icon: PH(100, 100, '06b6d4', 'FF') }, { id: '2', name: 'PUBG Mobile', icon: PH(100, 100, '3b82f6', 'PUBG') },
      { id: '3', name: 'Mobile Legends', icon: PH(100, 100, '8b5cf6', 'MLBB') }, { id: '4', name: 'Other Games', icon: PH(100, 100, 'ec4899', 'OTHER') }]);
    await ins('accounts', [
      { id: 'acc-101', game: 'Free Fire', title: 'Rare Incubator VIP Account', level: 72, price: 25, status: 'Available', desc: 'Includes 5 Evo Weapons Max, Hip Hop Season 1 Bundle.', images: [PH(600, 350, '06b6d4', 'Free+Fire+VIP')] },
      { id: 'acc-102', game: 'PUBG Mobile', title: 'M416 Glacier Max + Conqueror', level: 68, price: 45, status: 'Available', desc: 'M416 Glacier Lv 7, Mythic Fashion.', images: [PH(600, 350, '3b82f6', 'PUBG+Glacier')] },
      { id: 'acc-103', game: 'Mobile Legends', title: 'All Heroes + Collector Skins', level: 80, price: 30, status: 'Available', desc: 'Full Emblem Max, 250+ Skins.', images: [PH(600, 350, '8b5cf6', 'Mobile+Legends')] }]);
    await ins('banners', [{ id: 'b1', image: PH(1000, 400, '06b6d4', 'Welcome+to+G+martt') }, { id: 'b2', image: PH(1000, 400, '3b82f6', 'Instant+Account+Delivery') }]);
    const sv = [['Top Up Game Diamonds', 'Instant diamond & UC top up', '06b6d4', 'Top+Up'], ['Middleman Escrow', 'Safe & secure trade escrow', '3b82f6', 'Escrow'],
      ['Account Recovery', 'Lost account security help', '8b5cf6', 'Recovery'], ['VIP Membership Pass', 'Exclusive discount pass', 'ec4899', 'VIP+Pass'],
      ['Account Appraisal', 'Free market account check', '14b8a6', 'Appraisal'], ['Express Account Transfer', 'Safe login detail handoff', 'f59e0b', 'Transfer']];
    await ins('services', sv.map((s, i) => ({ id: 's' + (i + 1), title: s[0], desc: s[1], image: PH(300, 200, s[2], s[3]), link: 'https://t.me/zicksiik' })));
    await d.collection('settings').insertOne({ _id: 'seeded', value: 1 });
  })().catch(e => { seeding = null; throw e; });
  return seeding;
}

/* ---------- helpers ---------- */
const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
const out = ({ _id, ts, ...r }) => ({ id: _id, ...r });
const list = async (d, name) => (await d.collection(name).find().sort({ ts: 1 }).toArray()).map(out);
const newOrderId = () => `GM-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${crypto.randomInt(1000, 10000)}`;

/* ---------- public routes ---------- */
app.get('/api/data', wrap(async (req, res) => {
  await ensureSeed();
  const d = await getDb();
  const [categories, accounts, banners, services, settings] = await Promise.all([
    list(d, 'categories'), list(d, 'accounts'), list(d, 'banners'), list(d, 'services'),
    d.collection('settings').find({ _id: { $in: SETTING_KEYS } }).toArray()
  ]);
  res.json({ categories, accounts, banners, services, settings: settings.map(s => ({ key: s._id, value: s.value })) });
}));

app.post('/api/login', wrap(async (req, res) => {
  if (tooMany(req.ip)) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const pw = String((req.body || {}).password ?? '');
  const d = await getDb();
  const rec = await d.collection('settings').findOne({ _id: 'admin_password_hash' });
  let ok = false;
  if (rec) ok = checkPw(pw, rec.value);
  else if (process.env.ADMIN_PASSWORD) ok = crypto.timingSafeEqual(sha(pw), sha(process.env.ADMIN_PASSWORD));
  else return res.status(500).json({ error: 'ADMIN_PASSWORD is not set on the server' });
  if (!ok) { attempts.get(req.ip).push(Date.now()); return res.status(401).json({ error: 'Invalid Password!' }); }
  res.json({ token: makeToken() });
}));

// Atomic purchase: only one buyer can flip Available -> Sold
app.post('/api/order', wrap(async (req, res) => {
  const b = req.body || {};
  const customerName = str(b.customerName, 80);
  if (!customerName) return res.status(400).json({ error: 'Name is required' });
  if (!validId(b.accountId)) return res.status(400).json({ error: 'Invalid account' });
  const d = await getDb();
  const acc = await d.collection('accounts').findOneAndUpdate({ _id: String(b.accountId), status: 'Available' }, { $set: { status: 'Sold' } }, { returnDocument: 'after' });
  if (!acc) return res.status(409).json({ error: 'Sorry, this account is no longer available.' });
  let id = /^GM-\d{8}-\d{4}$/.test(b.orderId || '') ? b.orderId : newOrderId();
  const doc = { customerName, gameId: str(b.gameId, 80), accountId: acc._id, accountTitle: acc.title, price: acc.price, createdAt: new Date().toISOString() };
  try { await d.collection('orders').insertOne({ _id: id, ...doc }); }
  catch (e) { if (e.code !== 11000) throw e; id = newOrderId(); await d.collection('orders').insertOne({ _id: id, ...doc }); }
  res.json({ id, ...doc });
}));

/* ---------- admin routes ---------- */
app.get('/api/orders', auth, wrap(async (req, res) => {
  const d = await getDb();
  res.json((await d.collection('orders').find().sort({ createdAt: -1 }).toArray()).map(out));
}));
app.delete('/api/orders', auth, wrap(async (req, res) => { await (await getDb()).collection('orders').deleteMany({}); res.json({ ok: true }); }));
app.delete('/api/orders/:id', auth, wrap(async (req, res) => {
  if (!validId(req.params.id)) return res.status(400).json({ error: 'Invalid id' });
  await (await getDb()).collection('orders').deleteOne({ _id: req.params.id }); res.json({ ok: true });
}));

app.put('/api/password', auth, wrap(async (req, res) => {
  const pw = String((req.body || {}).password ?? '');
  if (pw.length < 6 || pw.length > 128) return res.status(400).json({ error: 'Password must be 6-128 characters' });
  await (await getDb()).collection('settings').updateOne({ _id: 'admin_password_hash' }, { $set: { value: hashPw(pw) } }, { upsert: true });
  res.json({ ok: true });
}));

app.put('/api/settings/:key', auth, wrap(async (req, res) => {
  const key = req.params.key;
  if (!SETTING_KEYS.includes(key)) return res.status(400).json({ error: 'Unknown setting' });
  const value = img((req.body || {}).value);
  if (!value) return res.status(400).json({ error: 'A valid image is required' });
  await (await getDb()).collection('settings').updateOne({ _id: key }, { $set: { value } }, { upsert: true });
  res.json({ key, value });
}));

app.put('/api/:store/:id', auth, wrap(async (req, res) => {
  const { store, id } = req.params;
  if (!SCHEMA[store]) return res.status(404).json({ error: 'Unknown store' });
  if (!validId(id)) return res.status(400).json({ error: 'Invalid id' });
  const clean = SCHEMA[store](req.body || {});
  if (!clean[REQUIRED[store]]) return res.status(400).json({ error: `${REQUIRED[store]} is required` });
  await (await getDb()).collection(store).updateOne({ _id: id }, { $set: clean, $setOnInsert: { ts: Date.now() } }, { upsert: true });
  res.json({ id, ...clean });
}));

app.delete('/api/:store/:id', auth, wrap(async (req, res) => {
  const { store, id } = req.params;
  if (!SCHEMA[store]) return res.status(404).json({ error: 'Unknown store' });
  if (!validId(id)) return res.status(400).json({ error: 'Invalid id' });
  await (await getDb()).collection(store).deleteOne({ _id: id });
  res.json({ ok: true });
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  console.error(err);
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Upload too large. Use smaller images.' });
  res.status(err.status || 500).json({ error: err.status ? err.message : 'Server error' });
});

module.exports = app;

// Local development: node server.js
if (require.main === module) {
  app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`G martt running on http://localhost:${port}`));
}
