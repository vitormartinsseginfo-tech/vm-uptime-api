// server.js - SUPER SERVIDOR VM SECURITY (UNIFICADO) - v2 (com /api/check-now e logs)
const express = require('express');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const UserAgent = require('user-agents');
const admin = require('firebase-admin');

const app = express();
app.use(express.json());

// ---------- CONFIGURAÇÕES ----------
const PORT = process.env.PORT || 10000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const MONITOR_INTERVAL = parseInt(process.env.MONITOR_INTERVAL || '600000'); // 10 min
const MASTER_KEY = process.env.MASTER_KEY || null;

// ---------- MIDDLEWARE: LOG DE REQUISIÇÕES (DEBUG) ----------
app.use((req, res, next) => {
  console.log(`[REQ] ${new Date().toISOString()} - ${req.method} ${req.originalUrl} - Origin: ${req.headers.origin || '-'}`);
  // continue
  next();
});

// ---------- CORREÇÃO DEFINITIVA DE CORS ----------
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin) {
        // Espelhar Origin (não usar '*') para permitir credentials
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE, PUT');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Master-Key, X-Requested-With');

    // Responder preflight OPTIONS
    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }
    next();
});

// ---------- FIREBASE ADMIN (OPCIONAL) ----------
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
        const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
        if (!admin.apps.length) {
            admin.initializeApp({ credential: admin.credential.cert(sa) });
        }
        console.log('✅ Firebase Admin inicializado');
    } catch (e) {
        console.error('❌ Erro ao inicializar Firebase Admin:', e.message);
    }
}

// ---------- HTTP CLIENT ----------
const client = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 20000
});

// ---------- ARMAZENAMENTO SIMPLES ----------
let DB = { sites: [] };
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      DB = JSON.parse(fs.readFileSync(DATA_FILE));
      console.log('🔁 Dados carregados de', DATA_FILE);
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

// ---------- MIDDLEWARE DE AUTENTICAÇÃO ----------
async function requireAuth(req, res, next) {
  // Se não configurado Firebase nem MASTER_KEY => ambiente de desenvolvimento (liberado)
  if (!process.env.FIREBASE_SERVICE_ACCOUNT && !MASTER_KEY) return next();

  // Master Key header
  const mk = req.headers['x-master-key'] || req.headers['x-masterkey'];
  if (MASTER_KEY && mk === MASTER_KEY) return next();

  // Auth via Firebase Bearer token
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

// ---------- ROUTES ----------

// Health / keepalive
app.get('/', (req, res) => {
  res.json({ status: 'online', uptime: process.uptime(), sites: DB.sites.length });
});

// CONTACT HUNTER
app.get('/hunt', requireAuth, async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: 'URL obrigatória' });
  try {
    const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
    const resp = await client.get(targetUrl, { headers: { 'User-Agent': ua } });
    const html = resp.data || '';
    const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
    const phoneRegex = /(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)(?:9\d{4}|\d{4})[-\.\s]?\d{4}/g;
    const socialRegex = /(facebook|instagram|linkedin|twitter|wa\.me|api\.whatsapp)\.com\/[a-zA-Z0-9._\/-]+/g;
    const emails = [...new Set(html.match(emailRegex) || [])];
    const phones = [...new Set(html.match(phoneRegex) || [])];
    const socials = [...new Set(html.match(socialRegex) || [])].map(s => s.startsWith('http') ? s : 'https://' + s);
    res.json({ emails, phones, socials });
  } catch (e) {
    console.error('/hunt error:', e.message);
    res.status(500).json({ error: 'Erro no Hunter', details: e.message });
  }
});

// ANALYZE (security headers)
app.get('/analyze', requireAuth, async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: 'URL obrigatória' });
  try {
    const resp = await client.get(targetUrl, { validateStatus: () => true });
    const h = resp.headers || {};
    res.json({
      status: resp.status,
      securityHeaders: {
        'x-frame-options': h['x-frame-options'] || 'MISSING',
        'strict-transport-security': h['strict-transport-security'] || 'MISSING',
        'content-security-policy': h['content-security-policy'] || 'MISSING',
        'x-content-type-options': h['x-content-type-options'] || 'MISSING'
      }
    });
  } catch (e) {
    console.error('/analyze error:', e.message);
    res.status(500).json({ error: 'Erro no Scan', details: e.message });
  }
});

// UPTIME: listar sites
app.get('/api/sites', requireAuth, (req, res) => {
  res.json(DB.sites.map(s => ({ id: s.id, url: s.url, name: s.name, lastCheck: s.lastCheck })));
});

// UPTIME: adicionar site
app.post('/api/sites', requireAuth, (req, res) => {
  const { url, name } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url é obrigatória' });
  const n = url.trim();
  const site = { id: Date.now().toString(36), url: n, name: name || n, history: [], lastCheck: null, createdAt: new Date().toISOString() };
  DB.sites.push(site);
  saveData();
  res.json(site);
});

// UPTIME: remover site
app.delete('/api/sites/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  const idx = DB.sites.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ error: 'site não encontrado' });
  DB.sites.splice(idx, 1);
  saveData();
  res.json({ ok: true });
});

// função de checagem
async function checkSite(site) {
  const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
  const start = Date.now();
  try {
    const resp = await client.get(site.url, { headers: { 'User-Agent': ua }, validateStatus: () => true });
    const elapsed = Date.now() - start;
    const record = { at: new Date().toISOString(), up: resp.status >= 200 && resp.status < 400, status: resp.status, latency_ms: elapsed };
    site.lastCheck = record;
    site.history = (site.history || []).slice(-199).concat(record);
    return record;
  } catch (e) {
    const elapsed = Date.now() - start;
    const record = { at: new Date().toISOString(), up: false, error: e.message, latency_ms: elapsed };
    site.lastCheck = record;
    site.history = (site.history || []).slice(-199).concat(record);
    return record;
  }
}

// rotina para checar todos
let schedulerRunning = false;
async function runChecks() {
  if (schedulerRunning) return;
  schedulerRunning = true;
  console.log('⏱️ Iniciando checagem de sites:', DB.sites.length);
  for (const s of DB.sites) {
    try {
      console.log('➡️ Checando', s.url);
      await checkSite(s);
    } catch (e) {
      console.error('Erro ao checar', s.url, e.message);
    }
  }
  saveData();
  console.log('✅ Checagens concluídas');
  schedulerRunning = false;
}
setInterval(() => { if (DB.sites.length > 0) runChecks(); }, MONITOR_INTERVAL);

// NOVA ROTA: /api/check-now  (GET/POST) -> forçar checagens e retornar resumo
app.get('/api/check-now', requireAuth, async (req, res) => {
  try {
    await runChecks();
    const summary = DB.sites.map(s => ({ id: s.id, url: s.url, lastCheck: s.lastCheck }));
    res.json({ ok: true, summary });
  } catch (e) {
    console.error('/api/check-now error:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// POST também disponível (aceita body { id } para checar só 1 site opcionalmente)
app.post('/api/check-now', requireAuth, async (req, res) => {
  try {
    const { id } = req.body || {};
    if (id) {
      const site = DB.sites.find(s => s.id === id);
      if (!site) return res.status(404).json({ error: 'site não encontrado' });
      const result = await checkSite(site);
      saveData();
      return res.json({ ok: true, id: site.id, url: site.url, result });
    } else {
      await runChecks();
      const summary = DB.sites.map(s => ({ id: s.id, url: s.url, lastCheck: s.lastCheck }));
      return res.json({ ok: true, summary });
    }
  } catch (e) {
    console.error('/api/check-now POST error:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// histórico de um site
app.get('/api/site/:id/history', requireAuth, (req, res) => {
  const site = DB.sites.find(s => s.id === req.params.id);
  if (!site) return res.status(404).json({ error: 'site não encontrado' });
  res.json({ id: site.id, history: site.history || [] });
});

// start
app.listen(PORT, () => {
  console.log(`🚀 Super servidor rodando na porta ${PORT}`);
  console.log(`MONITOR_INTERVAL=${MONITOR_INTERVAL}ms, DATA_FILE=${DATA_FILE}`);
});
