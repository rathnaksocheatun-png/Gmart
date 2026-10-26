const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json({ limit: '4mb' }));

const COLS = ['accounts', 'categories', 'banners', 'services', 'orders', 'settings', 'music'];
const PUBLIC_SETTINGS = ['khqr_image', 'site_logo'];
const SECRET = process.env.TOKEN_SECRET || process.env.MONGODB_URI || 'change-me';
const DEFAULT_PASSWORD = process.env.ADMIN_PASSWORD || 'ceogmart@2026';

/* ---------- MongoDB (connection reused between serverless calls) ---------- */
let clientPromise, seedPromise;
async function getDb() {
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is not set');
  if (!clientPromise) clientPromise = MongoClient.connect(process.env.MONGODB_URI);
  const db = (await clientPromise).db(process.env.DB_NAME || 'gmartt');
  if (!seedPromise) seedPromise = seed(db).catch(e => { seedPromise = null; throw e; });
  await seedPromise;
  return db;
}

async function seed(db) {
  const flag = db.collection('settings');
  if (await flag.findOne({ _id: 'seeded' })) return;
  const ins = (c, docs, key = 'id') => docs.length && db.collection(c).insertMany(docs.map(d => ({ ...d, _id: d[key] })));
  const ph = (w, h, c, t) => `https://placehold.co/${w}x${h}/${c}/ffffff?text=${t}`;
  await ins('categories', [
    { id: '1', name: 'Free Fire', icon: ph(100, 100, '10b981', 'FF') },
    { id: '2', name: 'PUBG Mobile', icon: ph(100, 100, '3b82f6', 'PUBG') },
    { id: '3', name: 'Mobile Legends', icon: ph(100, 100, 'f59e0b', 'MLBB') },
    { id: '4', name: 'Other Games', icon: ph(100, 100, '8b5cf6', 'OTHER') }
  ]);
  await ins('accounts', [
    { id: 'acc-101', game: 'Free Fire', title: 'Rare Incubator VIP Account', level: 72, price: 25, status: 'Available', desc: 'Includes 5 Evo Weapons Max, Hip Hop Season 1 Bundle, 80+ Emotes.', images: [ph(600, 350, '10b981', 'Free+Fire+VIP')] },
    { id: 'acc-102', game: 'PUBG Mobile', title: 'M416 Glacier Max + Conqueror', level: 68, price: 45, status: 'Available', desc: 'M416 Glacier Lv 7, Conqueror Frame, Mythic Fashion.', images: [ph(600, 350, '3b82f6', 'PUBG+Glacier')] },
    { id: 'acc-103', game: 'Mobile Legends', title: 'All Heroes + Collector Skins', level: 80, price: 30, status: 'Available', desc: 'Full Emblem Max, 250+ Skins.', images: [ph(600, 350, 'f59e0b', 'Mobile+Legends')] }
  ]);
  await ins('banners', [
    { id: 'b1', image: ph(1000, 400, '10b981', 'Welcome+to+G+martt') },
    { id: 'b2', image: ph(1000, 400, '059669', 'Instant+Account+Delivery') }
  ]);
  const sv = [['Top Up Game Diamonds', 'Instant diamond & UC top up', '10b981'], ['Middleman Escrow', 'Safe & secure trade escrow', '3b82f6'],
    ['Account Recovery', 'Lost account security help', 'f59e0b'], ['VIP Membership Pass', 'Exclusive discount pass', '8b5cf6'],
    ['Account Appraisal', 'Free market account check', 'ec4899'], ['Express Account Transfer', 'Safe login detail handoff', '14b8a6']];
  await ins('services', sv.map(([title, desc, c], i) => ({ id: 's' + (i + 1), title, desc, image: ph(300, 200, c, 'G+martt'), link: 'https://t.me/zicksiik' })));
  await flag.insertOne({ _id: 'seeded', key: 'seeded', value: 1 });
}

/* ---------- Auth (signed 12h token) ---------- */
const sign = exp => exp + '.' + crypto.createHmac('sha256', SECRET).update(String(exp)).digest('hex');
const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const isAdmin = req => { const t = (req.headers.authorization || '').replace('Bearer ', ''); const [exp] = t.split('.'); return !!exp && +exp > Date.now() && safeEq(sign(exp), t); };
const needAdmin = (req, res, next) => isAdmin(req) ? next() : res.status(401).json({ error: 'unauthorized' });

const hashPw = pw => { const s = crypto.randomBytes(16).toString('hex'); return s + ':' + crypto.scryptSync(pw, s, 32).toString('hex'); };
const checkPw = (pw, stored) => { const [s, h] = stored.split(':'); return safeEq(crypto.scryptSync(pw, s, 32).toString('hex'), h); };

const tries = new Map(); // simple per-IP brute-force limit (best effort on serverless)
app.post('/api/login', async (req, res, next) => {
  try {
    const ip = req.headers['x-forwarded-for'] || req.ip, now = Date.now();
    const rec = (tries.get(ip) || []).filter(t => now - t < 60000);
    if (rec.length >= 5) return res.status(429).json({ error: 'Too many attempts. Wait a minute.' });
    const db = await getDb();
    const doc = await db.collection('settings').findOne({ _id: 'admin_password' });
    const pw = String((req.body || {}).password || '');
    const ok = doc ? checkPw(pw, doc.value) : safeEq(pw, DEFAULT_PASSWORD);
    if (!ok) { rec.push(now); tries.set(ip, rec); return res.status(401).json({ error: 'Invalid password' }); }
    res.json({ token: sign(now + 12 * 3600 * 1000) });
  } catch (e) { next(e); }
});

/* ---------- Customer checkout: server marks the account Sold atomically ---------- */
app.post('/api/order', async (req, res, next) => {
  try {
    const b = req.body || {};
    const name = String(b.customerName || '').trim().slice(0, 80);
    if (!name) return res.status(400).json({ error: 'Name required' });
    const db = await getDb();
    const acc = await db.collection('accounts').findOneAndUpdate(
      { _id: String(b.accountId), status: 'Available' }, { $set: { status: 'Sold' } }, { returnDocument: 'after' });
    const a = acc && (acc.value || acc);
    if (!a || !a._id) return res.status(409).json({ error: 'Account no longer available' });
    const id = `GM-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${crypto.randomInt(1000, 9999)}`;
    const order = { id, _id: id, customerName: name, customerGameId: String(b.customerGameId || '').trim().slice(0, 80),
      accountId: a.id, accountTitle: a.title, game: a.game, level: a.level, price: a.price, paymentStatus: 'Pending Review', createdAt: new Date().toISOString() };
    await db.collection('orders').insertOne(order);
    delete order._id;
    res.json(order);
  } catch (e) { next(e); }
});

/* ---------- Generic collection API ---------- */
const colCheck = (req, res, next) => COLS.includes(req.params.col) ? next() : res.status(404).json({ error: 'unknown collection' });
const clean = ({ _id, ...d }) => d;

app.get('/api/:col', colCheck, async (req, res, next) => {
  try {
    const { col } = req.params, admin = isAdmin(req);
    if (col === 'orders' && !admin) return res.status(401).json({ error: 'unauthorized' });
    const docs = await (await getDb()).collection(col).find({}).toArray();
    let out = docs.map(clean);
    if (col === 'settings') out = out.filter(d => d.key !== 'seeded' && d.key !== 'admin_password' && (admin || PUBLIC_SETTINGS.includes(d.key)));
    res.set('Cache-Control', 'no-store').json(out);
  } catch (e) { next(e); }
});

app.put('/api/:col/:id', colCheck, needAdmin, async (req, res, next) => {
  try {
    const { col, id } = req.params;
    const doc = { ...req.body };
    if (col === 'settings') {
      doc.key = id;
      if (id === 'admin_password') {
        if (String(doc.value || '').length < 6) return res.status(400).json({ error: 'Password too short' });
        doc.value = hashPw(String(doc.value));
      }
    } else doc.id = id;
    await (await getDb()).collection(col).replaceOne({ _id: id }, { ...doc, _id: id }, { upsert: true });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

app.delete('/api/:col/:id', colCheck, needAdmin, async (req, res, next) => {
  try {
    await (await getDb()).collection(req.params.col).deleteOne({ _id: req.params.id });
    res.json({ ok: true });
  } catch (e) { next(e); }
});

/* ---------- Frontend ---------- */
app.use((req, res) => req.path.startsWith('/api/') ? res.status(404).json({ error: 'not found' }) : res.sendFile(path.join(__dirname, 'index.html')));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Server error' }); });

module.exports = app;
if (require.main === module) app.listen(process.env.PORT || 3000, () => console.log('G martt running on http://localhost:' + (process.env.PORT || 3000)));
