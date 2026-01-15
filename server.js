// server.js - SUPER SERVIDOR UNIFICADO VM SECURITY - v9 (FULL FIX)
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
const DATA_FILE = path.join(__dirname, 'data.json');
const MONITOR_INTERVAL = parseInt(process.env.MONITOR_INTERVAL || '600000');
const MASTER_KEY = process.env.MASTER_KEY || null;

// ---------- CORS DEFINITIVO (Reflexivo) ----------
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE, PUT');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Master-Key');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

// ---------- BANCO DE DADOS ----------
let DB = { sites: [], leakMonitor: { domains: [] } };
function loadData() {
    if (fs.existsSync(DATA_FILE)) {
        try { DB = JSON.parse(fs.readFileSync(DATA_FILE)); } catch (e) { console.error("Erro ao ler DB"); }
    }
}
function saveData() { fs.writeFileSync(DATA_FILE, JSON.stringify(DB, null, 2)); }
loadData();

const client = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 30000,
    maxRedirects: 5
});

// ---------- AUTH ----------
async function requireAuth(req, res, next) {
    if (!process.env.FIREBASE_SERVICE_ACCOUNT && !MASTER_KEY) return next();
    const mk = req.headers['x-master-key'] || req.headers['x-masterkey'];
    if (MASTER_KEY && mk === MASTER_KEY) return next();
    next();
}

// ---------- ROTEADOR INTELIGENTE ----------
const router = express.Router();

// ROTA DE STATUS (Para você não ver mais o erro de Rota não encontrada)
router.get('/', (req, res) => {
    res.json({ 
        status: "online", 
        message: "VM Security API Unificada",
        tools: ["Hunter", "24x7", "Vulnerability", "LeakHunter"],
        database: { sites: DB.sites.length, leakDomains: DB.leakMonitor.domains.length }
    });
});

// --- FERRAMENTA: HUNTER ---
router.all('/hunt', requireAuth, async (req, res) => {
    const target = req.query.url || (req.body && req.body.url);
    if (!target) return res.status(400).json({ error: 'URL missing' });
    try {
        const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
        const url = target.startsWith('http') ? target : 'http://' + target;
        const resp = await client.get(url, { headers: { 'User-Agent': ua } });
        const html = resp.data || '';
        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        const phoneRegex = /(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)(?:9\d{4}|\d{4})[-\.\s]?\d{4}/g;
        res.json({
            emails: [...new Set(html.match(emailRegex) || [])],
            phones: [...new Set(html.match(phoneRegex) || [])],
            socials: []
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- FERRAMENTA: VULNERABILITY ---
const analyzeHandler = async (req, res) => {
    const target = req.query.url || (req.body && req.body.url);
    if (!target) return res.status(400).json({ error: 'URL missing' });
    try {
        const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
        const url = target.startsWith('http') ? target : 'http://' + target;
        const resp = await client.get(url, { headers: { 'User-Agent': ua }, validateStatus: () => true });
        const h = resp.headers || {};
        res.json({
            status: resp.status,
            server: h['server'] || 'Não detectado',
            technology: h['x-powered-by'] || 'Não detectada',
            securityHeaders: {
                'x-frame-options': h['x-frame-options'] || 'MISSING',
                'strict-transport-security': h['strict-transport-security'] || 'MISSING',
                'content-security-policy': h['content-security-policy'] || 'MISSING',
                'x-content-type-options': h['x-content-type-options'] || 'MISSING'
            }
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
};
router.all('/analyze', requireAuth, analyzeHandler);
router.all('/scan', requireAuth, analyzeHandler);
router.all('/api/scan', requireAuth, analyzeHandler);

// --- FERRAMENTA: 24x7 (UPTIME) ---
router.get('/sites', requireAuth, (req, res) => res.json(DB.sites));
router.post('/sites', requireAuth, async (req, res) => {
    const site = { id: Date.now().toString(36), url: req.body.url, lastCheck: null };
    DB.sites.push(site);
    saveData();
    res.json(site);
});
router.delete('/sites/:id', requireAuth, (req, res) => {
    DB.sites = DB.sites.filter(s => s.id !== req.params.id);
    saveData();
    res.json({ ok: true });
});
router.all('/check-now', requireAuth, async (req, res) => {
    const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
    for (const s of DB.sites) {
        try {
            const url = s.url.startsWith('http') ? s.url : 'http://' + s.url;
            const r = await client.get(url, { headers: { 'User-Agent': ua }, validateStatus: () => true });
            s.lastCheck = { at: new Date().toISOString(), up: r.status < 400, status: r.status };
        } catch (e) { s.lastCheck = { at: new Date().toISOString(), up: false }; }
    }
    saveData();
    res.json({ ok: true });
});

// --- FERRAMENTA: VM LEAK ---
router.get('/monitor/domains', requireAuth, (req, res) => res.json(DB.leakMonitor.domains));
router.post('/monitor/domains', requireAuth, (req, res) => {
    const domain = { id: Date.now().toString(36), domain: req.body.domain, lastCheck: { up: true } };
    DB.leakMonitor.domains.push(domain);
    saveData();
    res.json(domain);
});
router.delete('/monitor/domains/:id', requireAuth, (req, res) => {
    DB.leakMonitor.domains = DB.leakMonitor.domains.filter(d => d.id !== req.params.id);
    saveData();
    res.json({ ok: true });
});

// APLICA O ROTEADOR
app.use('/api', router);
app.use('/', router);

// RESPOSTA PADRÃO JSON
app.use((req, res) => res.status(404).json({ error: "Rota não encontrada", path: req.url }));

app.listen(PORT, () => console.log(`🚀 Servidor Unificado na porta ${PORT}`));
