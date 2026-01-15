// server.js - VM-LEAK / Super Servidor Unificado - correção geral (COMPLETO)
const express = require('express');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const UserAgent = require('user-agents');
const admin = require('firebase-admin');

const app = express();
app.use(express.json());

// ---------- CONFIG ----------
const PORT = process.env.PORT || 10000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const MONITOR_INTERVAL = parseInt(process.env.MONITOR_INTERVAL || '600000'); // 10min default
const MASTER_KEY = process.env.MASTER_KEY || null;

// ---------- LOG (útil para Render) ----------
app.use((req, res, next) => {
  console.log(`[REQ] ${new Date().toISOString()} ${req.method} ${req.originalUrl} Origin:${req.headers.origin || '-'}`);
  next();
});

// ---------- CORS reflexivo (permite credentials) ----------
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Master-Key, X-Requested-With');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ---------- FIREBASE ADMIN (opcional) ----------
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
  try {
    const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa) });
    console.log('✅ Firebase Admin initialized');
  } catch (e) {
    console.error('❌ Firebase init error:', e.message);
  }
}

// ---------- HTTP client ----------
const client = axios.create({
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  timeout: 25000,
  maxRedirects: 5
});

// ---------- STORAGE simples ----------
let DB = {
  sites: [],            // para uptime / 24x7 etc (compatibilidade)
  leakMonitor: {        // para VM Leak monitor (nomes isolados p/ segurança)
    domains: []
  }
};

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      if (raw && raw.trim()) {
        const parsed = JSON.parse(raw);
        DB = Object.assign(DB, parsed);
        console.log('🔁 Dados carregados:', DATA_FILE);
      }
    } else {
      console.log('⚠️ data file não existe — iniciando DB vazio');
      saveData();
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

// ---------- AUTH flexível ----------
async function requireAuth(req, res, next) {
  if (!process.env.FIREBASE_SERVICE_ACCOUNT && !MASTER_KEY) return next();
  const mk = req.headers['x-master-key'] || req.headers['x-masterkey'];
  if (MASTER_KEY && mk === MASTER_KEY) return next();
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Não autorizado (token ausente)' });
  }
  try {
    const token = authHeader.split(' ')[1];
    await admin.auth().verifyIdToken(token);
    return next();
  } catch (e) {
    console.error('Firebase verify error:', e.message);
    return res.status(401).json({ error: 'Token inválido' });
  }
}

// ---------- HELPERS ----------
function normalizeUrl(u) {
  if (!u) return null;
  let url = String(u).trim();
  if (!/^https?:\/\//i.test(url)) url = 'http://' + url;
  return url;
}

function notFoundJson(res, path) {
  return res.status(404).json({ error: 'not_found', path });
}

// ---------- MONITOR: checagem (reutilizável) ----------
async function checkDomainRecord(domainObj) {
  const start = Date.now();
  try {
    const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
    const url = normalizeUrl(domainObj.url || domainObj.domain || domainObj.target);
    const resp = await client.get(url, {
      headers: { 'User-Agent': ua, Accept: 'text/html,application/json,*/*' },
      validateStatus: () => true
    });
    const elapsed = Date.now() - start;
    const record = {
      at: new Date().toISOString(),
      up: resp.status >= 200 && resp.status < 400,
      status: resp.status,
      latency_ms: elapsed
    };
    domainObj.lastCheck = record;
    domainObj.history = (domainObj.history || []).slice(-199).concat(record);
    return record;
  } catch (e) {
    const elapsed = Date.now() - start;
    const record = { at: new Date().toISOString(), up: false, error: e.message, latency_ms: elapsed };
    domainObj.lastCheck = record;
    domainObj.history = (domainObj.history || []).slice(-199).concat(record);
    return record;
  }
}

async function runAllLeakChecks() {
  console.log('⏱️ runAllLeakChecks - domains:', DB.leakMonitor.domains.length);
  for (const d of DB.leakMonitor.domains) {
    try {
      console.log('➡️ checking leak domain', d.domain || d.url);
      await checkDomainRecord(d);
    } catch (e) {
      console.error('Erro checkDomainRecord:', e.message);
    }
  }
  saveData();
  console.log('✅ runAllLeakChecks finished');
}

// agenda automática (somente se tiver domínios)
setInterval(() => { if (DB.leakMonitor.domains.length > 0) runAllLeakChecks(); }, MONITOR_INTERVAL);

// ---------- ROTAS: VM Leak / monitor namespace ----------

// Health
app.get('/', (req, res) => res.json({ status: 'online', leakDomains: DB.leakMonitor.domains.length }));

// GET /monitor/domains  -> lista todos os domínios do VM Leak
app.get('/monitor/domains', requireAuth, (req, res) => {
  return res.json(DB.leakMonitor.domains.map(d => ({
    id: d.id,
    domain: d.domain,
    url: d.url,
    lastCheck: d.lastCheck || null,
    createdAt: d.createdAt || null
  })));
});

// GET /monitor/domains/:id  -> detalhe de 1 domínio
app.get('/monitor/domains/:id', requireAuth, (req, res) => {
  const id = req.params.id;
  const item = DB.leakMonitor.domains.find(d => d.id === id);
  if (!item) return notFoundJson(res, req.originalUrl);
  return res.json(item);
});

// POST /monitor/domains  -> criar / adicionar domínio para monitoramento
// aceita { domain: 'exemplo.com' } ou { url: 'https://exemplo.com' }
app.post('/monitor/domains', requireAuth, async (req, res) => {
  try {
    const { domain, url, name } = req.body || {};
    const target = domain || url;
    if (!target) return res.status(400).json({ error: 'domain_or_url_required' });
    const normalized = normalizeUrl(target);
    const entry = {
      id: Date.now().toString(36),
      domain: domain ? domain : null,
      url: normalized,
      name: name || normalized,
      createdAt: new Date().toISOString(),
      lastCheck: null,
      history: []
    };
    DB.leakMonitor.domains.push(entry);
    // checagem imediata para evitar interface ficar "sem informação"
    await checkDomainRecord(entry);
    saveData();
    return res.status(201).json(entry);
  } catch (e) {
    console.error('POST /monitor/domains error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// POST /monitor/domains/delete  -> compatibilidade (body: { id })
app.post('/monitor/domains/delete', requireAuth, (req, res) => {
  try {
    const id = req.body && (req.body.id || req.body.domainId);
    if (!id) return res.status(400).json({ error: 'id_required' });
    const idx = DB.leakMonitor.domains.findIndex(d => d.id === id);
    if (idx === -1) return res.status(404).json({ error: 'not_found' });
    DB.leakMonitor.domains.splice(idx, 1);
    saveData();
    return res.json({ ok: true });
  } catch (e) {
    console.error('POST /monitor/domains/delete error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// DELETE /monitor/domains/:id  -> remoção via DELETE (padrão)
app.delete('/monitor/domains/:id', requireAuth, (req, res) => {
  try {
    const id = req.params.id;
    const idx = DB.leakMonitor.domains.findIndex(d => d.id === id);
    if (idx === -1) return res.status(404).json({ error: 'not_found' });
    DB.leakMonitor.domains.splice(idx, 1);
    saveData();
    return res.json({ ok: true });
  } catch (e) {
    console.error('DELETE /monitor/domains/:id error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// POST /monitor/domains/:id/check  -> checar apenas 1 domínio (compatibilidade front)
app.post('/monitor/domains/:id/check', requireAuth, async (req, res) => {
  try {
    const id = req.params.id;
    const item = DB.leakMonitor.domains.find(d => d.id === id);
    if (!item) return res.status(404).json({ error: 'not_found' });
    const result = await checkDomainRecord(item);
    saveData();
    return res.json({ ok: true, result, id: item.id });
  } catch (e) {
    console.error('POST /monitor/domains/:id/check error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// GET /monitor/check-all (forçar checagem de todos)
app.get('/monitor/check-all', requireAuth, async (req, res) => {
  try {
    await runAllLeakChecks();
    return res.json({ ok: true, count: DB.leakMonitor.domains.length });
  } catch (e) {
    console.error('GET /monitor/check-all error:', e.message);
    return res.status(500).json({ error: e.message });
  }
});

// ---------- ROTA DE COMPATIBILIDADE: evitar HTML 404 do Express para rotas desconhecidas ----------
// Responder com JSON em vez de HTML para evitar "Unexpected token '<'"
app.use((req, res) => {
  console.warn('404 JSON for', req.method, req.originalUrl);
  res.status(404).json({ error: 'not_found', path: req.originalUrl });
});

// Error handler centralizado -> sempre JSON
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err && err.stack ? err.stack : err);
  res.status(500).json({ error: 'internal_server_error', details: String(err && err.message ? err.message : err) });
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`🚀 VM-Leak / Super Servidor rodando na porta ${PORT}`);
  console.log(`DATA_FILE=${DATA_FILE} MONITOR_INTERVAL=${MONITOR_INTERVAL}ms`);
});
