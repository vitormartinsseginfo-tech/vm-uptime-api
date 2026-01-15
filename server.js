// server.js - VM Security Unified API (compatível com seus HTMLs)
const express = require('express');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const UserAgent = require('user-agents');
const admin = require('firebase-admin');

const app = express();
app.use(express.json());

// CONFIG
const PORT = process.env.PORT || 10000;
const DATA_FILE = path.join(__dirname, 'data.json');
const MONITOR_INTERVAL = parseInt(process.env.MONITOR_INTERVAL || '600000'); // 10min
const MASTER_KEY = process.env.MASTER_KEY || null;

// SIMPLE LOG
app.use((req, res, next) => {
  console.log(`[REQ] ${new Date().toISOString()} ${req.method} ${req.originalUrl} Origin:${req.headers.origin || '-'}`);
  next();
});

// CORS reflexivo (permite credentials)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Master-Key, X-Requested-With');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// FIREBASE ADMIN (opcional)
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa) });
    console.log('✅ Firebase Admin inicializado');
  } catch (e) {
    console.error('❌ Erro Firebase Admin:', e.message);
  }
}

// HTTP client
const client = axios.create({
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  timeout: 30000,
  maxRedirects: 5
});

// STORAGE
let DB = { sites: [], leakMonitor: { domains: [] } };
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      if (raw && raw.trim()) {
        DB = Object.assign(DB, JSON.parse(raw));
        console.log('🔁 DB carregado:', DATA_FILE);
      }
    } else {
      saveData(); // cria arquivo inicial se não existir
    }
  } catch (e) { console.error('Erro ao carregar DB:', e.message); }
}
function saveData() {
  try { fs.writeFileSync(DATA_FILE, JSON.stringify(DB, null, 2)); }
  catch (e) { console.error('Erro ao salvar DB:', e.message); }
}
loadData();

// AUTH flexível
async function requireAuth(req, res, next) {
  if (!process.env.FIREBASE_SERVICE_ACCOUNT && !MASTER_KEY) return next();
  const mk = req.headers['x-master-key'] || req.headers['x-masterkey'];
  if (MASTER_KEY && mk === MASTER_KEY) return next();
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Não autorizado (token ausente)' });
  try {
    const token = authHeader.split(' ')[1];
    await admin.auth().verifyIdToken(token);
    return next();
  } catch (e) {
    console.error('Firebase verify error:', e.message);
    return res.status(401).json({ error: 'Token inválido' });
  }
}

// HELPERS
function normalizeUrl(u) {
  if (!u) return null;
  let url = String(u).trim();
  if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
  return url;
}

// CHECK SITE (gera campos compatíveis com o frontend)
async function checkSite(site) {
  const start = Date.now();
  const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
  try {
    const url = normalizeUrl(site.url || site.target || site.domain);
    const resp = await client.get(url, { headers: { 'User-Agent': ua }, validateStatus: () => true });
    const latency = Date.now() - start;
    // Ajusta os campos usados pelo front-end
    site.status = (resp.status >= 200 && resp.status < 400) ? 'online' : 'offline';
    site.response_ms = latency;
    site.last_check = new Date().toISOString();
    site.lastCheck = site.last_check; // compatibilidade interna
    site.history = (site.history || []).slice(-199).concat({ at: site.last_check, up: site.status === 'online', status: resp.status, latency_ms: latency });
    return { up: site.status === 'online', status: resp.status, latency_ms: latency };
  } catch (e) {
    const latency = Date.now() - start;
    site.status = 'offline';
    site.response_ms = latency;
    site.last_check = new Date().toISOString();
    site.lastCheck = site.last_check;
    site.history = (site.history || []).slice(-199).concat({ at: site.last_check, up: false, error: e.message, latency_ms: latency });
    return { up: false, error: e.message };
  }
}

async function runChecksAllSites() {
  console.log('⏱️ runChecksAllSites - sites:', DB.sites.length);
  for (const s of DB.sites) {
    try { await checkSite(s); }
    catch (e) { console.error('Erro checkSite:', e.message); }
  }
  saveData();
  console.log('✅ runChecksAllSites finished');
}

// schedule automatic checks only if sites exist
setInterval(() => { if (DB.sites.length > 0) runChecksAllSites(); }, MONITOR_INTERVAL);

// ROUTER
const router = express.Router();

// STATUS root (para ver que tá online)
router.get('/', (req, res) => {
  res.json({ status: 'online', message: 'VM Security API', counts: { sites: DB.sites.length, leakDomains: DB.leakMonitor.domains.length } });
});

/* ---------------- UPTIME / 24x7 ---------------- */

// GET /api/sites  -> retorna lista NO FORMATO que o frontend espera
router.get('/sites', requireAuth, (req, res) => {
  const out = DB.sites.map(s => ({
    id: s.id,
    url: s.url,
    status: s.status || (s.lastCheck && s.lastCheck.up ? 'online' : 'offline'),
    response_ms: s.response_ms || (s.lastCheck ? s.lastCheck.latency_ms || 0 : 0),
    last_check: s.last_check || (s.lastCheck ? s.lastCheck.at : null),
    name: s.name || s.url
  }));
  res.json(out);
});

// POST /api/sites -> adiciona e faz checagem imediata, retorna objeto no formato esperado
router.post('/sites', requireAuth, async (req, res) => {
  try {
    const { url, name } = req.body || {};
    if (!url) return res.status(400).json({ error: 'url é obrigatória' });
    const normalized = normalizeUrl(url);
    const site = { id: Date.now().toString(36), url: normalized, name: name || normalized, history: [] };
    DB.sites.push(site);
    await checkSite(site); // checagem imediata
    saveData();
    return res.status(201).json({
      id: site.id,
      url: site.url,
      status: site.status,
      response_ms: site.response_ms,
      last_check: site.last_check,
      name: site.name
    });
  } catch (e) {
    console.error('POST /sites error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// DELETE /api/sites/:id -> remove (retorna ok)
router.delete('/sites/:id', requireAuth, (req, res) => {
  try {
    const id = req.params.id;
    const idx = DB.sites.findIndex(s => String(s.id) === String(id));
    if (idx === -1) return res.status(404).json({ error: 'site não encontrado' });
    DB.sites.splice(idx, 1);
    saveData();
    return res.json({ ok: true });
  } catch (e) {
    console.error('DELETE /sites error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// POST/GET /api/check-now -> força checagem e retorna resumo
async function checkNowHandler(req, res) {
  try {
    await runChecksAllSites();
    const summary = DB.sites.map(s => ({ id: s.id, url: s.url, status: s.status, response_ms: s.response_ms, last_check: s.last_check }));
    return res.json({ ok: true, summary });
  } catch (e) {
    console.error('/api/check-now error:', e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
}
router.get('/check-now', requireAuth, checkNowHandler);
router.post('/check-now', requireAuth, checkNowHandler);

/* ---------------- VULNERABILITY / SCANNER ---------------- */

// Esta rota retorna os campos que seu HTML espera:
// target, score, detected_server, detected_tech, vulnerabilities[]
router.all(['/analyze', '/scan', '/api/scan'], requireAuth, async (req, res) => {
  try {
    const targetRaw = req.query.url || (req.body && req.body.url);
    if (!targetRaw) return res.status(400).json({ error: 'URL missing' });
    const url = normalizeUrl(targetRaw);
    const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
    const resp = await client.get(url, { headers: { 'User-Agent': ua }, validateStatus: () => true });
    const h = resp.headers || {};
    const detected_server = h['server'] || h['via'] || 'Não detectado';
    let detected_tech = h['x-powered-by'] || h['x-generator'] || 'Não detectada';
    // tentativa simples por cookies
    if (Array.isArray(h['set-cookie'])) {
      const cookieJoin = h['set-cookie'].join(' ').toLowerCase();
      if (cookieJoin.includes('php')) detected_tech = detected_tech === 'Não detectada' ? 'PHP' : detected_tech;
      if (cookieJoin.includes('wordpress')) detected_tech = 'WordPress';
    }
    // montar formato que seu HTML espera
    const out = {
      target: url,
      score: 0, // se futuramente quiser calcular score, substitua aqui
      detected_server,
      detected_tech,
      securityHeaders: {
        'x-frame-options': h['x-frame-options'] || 'MISSING',
        'strict-transport-security': h['strict-transport-security'] || 'MISSING',
        'content-security-policy': h['content-security-policy'] || 'MISSING',
        'x-content-type-options': h['x-content-type-options'] || 'MISSING'
      },
      vulnerabilities: [] // por enquanto nada automatizado
    };
    return res.json(out);
  } catch (e) {
    console.error('/analyze error:', e.message);
    return res.status(500).json({ error: 'Erro no Scan', details: e.message });
  }
});

/* ---------------- VM-LEAK (monitor/domains) - compatibilidade ---------------- */

// listar
router.get('/monitor/domains', requireAuth, (req, res) => res.json(DB.leakMonitor.domains || []));

// adicionar (faz checagem simples)
router.post('/monitor/domains', requireAuth, async (req, res) => {
  try {
    const { domain, url } = req.body || {};
    const target = domain || url;
    if (!target) return res.status(400).json({ error: 'domain_or_url_required' });
    const normalized = normalizeUrl(target);
    const entry = { id: Date.now().toString(36), domain: domain || null, url: normalized, createdAt: new Date().toISOString(), lastCheck: null, history: [] };
    DB.leakMonitor.domains.push(entry);
    await checkSite(entry); // reuses checkSite to set last_check/status
    saveData();
    return res.status(201).json(entry);
  } catch (e) {
    console.error('POST /monitor/domains error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// delete compatibility
router.post('/monitor/domains/delete', requireAuth, (req, res) => {
  try {
    const id = req.body && (req.body.id || req.body.domainId);
    if (!id) return res.status(400).json({ error: 'id required' });
    const idx = DB.leakMonitor.domains.findIndex(d => String(d.id) === String(id));
    if (idx === -1) return res.status(404).json({ error: 'not_found' });
    DB.leakMonitor.domains.splice(idx, 1);
    saveData();
    return res.json({ ok: true });
  } catch (e) {
    console.error('POST /monitor/domains/delete error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

router.delete('/monitor/domains/:id', requireAuth, (req, res) => {
  try {
    const id = req.params.id;
    const idx = DB.leakMonitor.domains.findIndex(d => String(d.id) === String(id));
    if (idx === -1) return res.status(404).json({ error: 'not_found' });
    DB.leakMonitor.domains.splice(idx, 1);
    saveData();
    return res.json({ ok: true });
  } catch (e) { console.error('DELETE /monitor/domains/:id error:', e.message); return res.status(500).json({ error: e.message }); }
});

// apply router both on /api and root (compatibility)
app.use('/api', router);
app.use('/', router);

// JSON 404 handler to avoid HTML responses
app.use((req, res) => res.status(404).json({ error: 'Rota não encontrada', path: req.originalUrl }));

// Error handler (always JSON)
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err && err.stack ? err.stack : err);
  res.status(500).json({ error: 'internal_server_error', details: String(err && err.message ? err.message : err) });
});

// START
app.listen(PORT, () => {
  console.log(`🚀 VM Security API rodando na porta ${PORT}`);
  console.log(`DATA_FILE=${DATA_FILE} MONITOR_INTERVAL=${MONITOR_INTERVAL}ms`);
});
