// server.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const https = require('https');
const fs = require('fs');
const path = require('path');
const UserAgent = require('user-agents');
const admin = require('firebase-admin');
const { JSDOM } = require('jsdom');

const app = express();
app.use(express.json());

// ---------- CONFIG ----------
const PORT = process.env.PORT || 10000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const MONITOR_INTERVAL = parseInt(process.env.MONITOR_INTERVAL || '600000'); // 10 min default
const MAX_CRAWL_DEPTH = parseInt(process.env.MAX_CRAWL_DEPTH || '2');
const MASTER_KEY = process.env.MASTER_KEY || null; // fallback master password
// ----------------------------

// CORS: refletir origem (permite cookies/Authorization if frontend uses credentials)
app.use(cors({
  origin: (origin, cb) => cb(null, true),
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Master-Key']
}));

// Inicializa Firebase Admin se FIREBASE_SERVICE_ACCOUNT estiver definido (JSON string)
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    admin.initializeApp({ credential: admin.credential.cert(sa) });
    console.log('✅ Firebase Admin inicializado');
  } catch (e) {
    console.error('❌ Erro ao inicializar Firebase Admin:', e.message);
  }
}

// Axios client que ignora problemas SSL (útil para alguns alvos)
const client = axios.create({
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  timeout: 20000
});

// ---------- Simple storage (file) ----------
let DB = { sites: [] };
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      DB = JSON.parse(fs.readFileSync(DATA_FILE));
      console.log('🔁 Data loaded from', DATA_FILE);
    }
  } catch (e) {
    console.error('Erro ao carregar data file:', e.message);
  }
}
function saveData() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(DB, null, 2));
  } catch (e) {
    console.error('Erro ao salvar data file:', e.message);
  }
}
loadData();

// ---------- Auth middleware ----------
// Accepts valid Firebase token OR MASTER_KEY header
async function requireAuth(req, res, next) {
  // If no firebase and no master key configured, allow (dev)
  if (!process.env.FIREBASE_SERVICE_ACCOUNT && !MASTER_KEY) return next();

  // MASTER_KEY header (fallback)
  const mk = req.headers['x-master-key'] || req.headers['x-masterkey'];
  if (MASTER_KEY && mk && mk === MASTER_KEY) return next();

  // Firebase Authorization: Bearer <token>
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Não autorizado (token ausente)' });
  }
  const token = authHeader.split(' ')[1];
  try {
    await admin.auth().verifyIdToken(token);
    return next();
  } catch (e) {
    console.error('Firebase verify error:', e.message);
    return res.status(401).json({ error: 'Token inválido' });
  }
}

// ---------- Utility: decode Cloudflare email ----------
function decodeCloudflareEmail(encodedString) {
  try {
    let email = "";
    let r = parseInt(encodedString.substr(0, 2), 16);
    for (let n = 2; n < encodedString.length; n += 2) {
      let i = parseInt(encodedString.substr(n, 2), 16) ^ r;
      email += String.fromCharCode(i);
    }
    return email;
  } catch (e) {
    return null;
  }
}

// ---------- Contact Hunter endpoint ----------
app.get('/hunt', requireAuth, async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: 'URL obrigatória' });

  try {
    const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
    const resp = await client.get(targetUrl, {
      headers: {
        'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      }
    });
    let html = resp.data;

    // decode Cloudflare obfuscated emails
    const cf = [...(html.matchAll(/data-cfemail="([a-f0-9]+)"/g))].map(m => m[1]);
    cf.forEach(code => {
      const decoded = decodeCloudflareEmail(code);
      if (decoded) html += ' ' + decoded;
    });

    // regex
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const phoneRegex = /(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)(?:9\d{4}|\d{4})[-\.\s]?\d{4}/g;
    const socialRegex = /(https?:\/\/)?(www\.)?(facebook|instagram|linkedin|twitter|wa\.me|api\.whatsapp)\.com\/[a-zA-Z0-9._\/-]+/g;

    const emails = [...new Set(html.match(emailRegex) || [])];
    const phones = [...new Set((html.match(phoneRegex) || []).map(p => p.trim()))].filter(p => p.length >= 10);
    const socialsRaw = [...new Set(html.match(socialRegex) || [])];
    const socials = socialsRaw.map(s => s.startsWith('http') ? s : 'https://' + s);

    res.json({ emails, phones, socials });
  } catch (error) {
    console.error('Hunter error:', error.message);
    res.status(500).json({ error: 'Erro ao caçar contatos', details: error.message });
  }
});

// ---------- Simple Analyzer endpoint (security headers) ----------
app.get('/analyze', requireAuth, async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: 'URL obrigatória' });
  try {
    const resp = await client.get(targetUrl, { validateStatus: () => true });
    const headers = resp.headers || {};
    // basic checks
    const results = {
      status: resp.status,
      serverHeader: headers['server'] || null,
      securityHeaders: {
        'x-frame-options': headers['x-frame-options'] || null,
        'x-content-type-options': headers['x-content-type-options'] || null,
        'content-security-policy': headers['content-security-policy'] || null,
        'strict-transport-security': headers['strict-transport-security'] || null,
        'referrer-policy': headers['referrer-policy'] || null
      }
    };
    res.json(results);
  } catch (e) {
    console.error('Analyze error:', e.message);
    res.status(500).json({ error: 'Erro ao analisar site', details: e.message });
  }
});

// ---------- Uptime monitor logic ----------

// helper to normalize URL
function normalizeUrl(u) {
  try {
    const url = new URL(u);
    return url.href.replace(/\/+$/,''); // no trailing slash
  } catch(e) {
    // try to add https
    try {
      const url = new URL('https://' + u.replace(/^https?:\/\//,''));
      return url.href.replace(/\/+$/,'');
    } catch(err) {
      return null;
    }
  }
}

// create site entry
function createSite(url, name) {
  const n = normalizeUrl(url);
  if (!n) throw new Error('URL inválida');
  const site = {
    id: Date.now().toString(36),
    url: n,
    name: name || n,
    createdAt: new Date().toISOString(),
    lastCheck: null,
    history: []
  };
  DB.sites.push(site);
  saveData();
  return site;
}

// find site
function findSite(idOrUrl) {
  return DB.sites.find(s => s.id === idOrUrl || s.url === idOrUrl);
}

async function checkSite(site) {
  const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
  const start = Date.now();
  try {
    const resp = await client.get(site.url, {
      headers: { 'User-Agent': ua, 'Accept': 'text/html' },
      validateStatus: () => true
    });
    const elapsed = Date.now() - start;
    const record = {
      at: new Date().toISOString(),
      up: resp.status >= 200 && resp.status < 400,
      status: resp.status,
      latency_ms: elapsed
    };
    site.lastCheck = record;
    site.history = (site.history || []).slice(-200).concat(record); // keep history bounded
    saveData();
    return record;
  } catch (e) {
    const elapsed = Date.now() - start;
    const record = {
      at: new Date().toISOString(),
      up: false,
      status: null,
      latency_ms: elapsed,
      error: e.message
    };
    site.lastCheck = record;
    site.history = (site.history || []).slice(-200).concat(record);
    saveData();
    return record;
  }
}

// Background scheduler
let schedulerRunning = false;
async function runChecksAll() {
  if (schedulerRunning) return;
  schedulerRunning = true;
  console.log('⏱️ Iniciando checagem de sites:', DB.sites.length, 'sites');
  for (const s of DB.sites) {
    try {
      console.log('➡️ Checando', s.url);
      await checkSite(s);
    } catch (e) {
      console.error('Erro checando', s.url, e.message);
    }
  }
  console.log('✅ Checagens concluídas');
  schedulerRunning = false;
}

// start interval
setInterval(() => {
  if (DB.sites.length > 0) runChecksAll();
}, MONITOR_INTERVAL);

// ---------- HTTP routes for monitor management ----------
app.get('/api/sites', requireAuth, (req, res) => {
  res.json(DB.sites.map(s => ({ id: s.id, url: s.url, name: s.name, lastCheck: s.lastCheck })));
});

app.post('/api/sites', requireAuth, (req, res) => {
  const { url, name } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url é obrigatória' });
  try {
    const s = createSite(url, name);
    res.json(s);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.delete('/api/sites/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  const idx = DB.sites.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ error: 'site não encontrado' });
  DB.sites.splice(idx, 1);
  saveData();
  res.json({ ok: true });
});

app.post('/api/check-now', requireAuth, async (req, res) => {
  const { id } = req.body || {};
  if (id) {
    const site = findSite(id);
    if (!site) return res.status(404).json({ error: 'site não encontrado' });
    const result = await checkSite(site);
    return res.json({ id: site.id, url: site.url, result });
  } else {
    // check all
    await runChecksAll();
    return res.json({ message: 'All checks triggered' });
  }
});

app.get('/api/site/:id/history', requireAuth, (req, res) => {
  const site = findSite(req.params.id);
  if (!site) return res.status(404).json({ error: 'site não encontrado' });
  res.json({ id: site.id, history: site.history || [] });
});

// ---------- Simple health / keepalive ----------
app.get('/', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), sites: DB.sites.length });
});

// start server
app.listen(PORT, () => {
  console.log(`🚀 Super servidor rodando na porta ${PORT}`);
  console.log(`MONITOR_INTERVAL=${MONITOR_INTERVAL}ms, DATA_FILE=${DATA_FILE}`);
});
