// server.js - SUPER SERVIDOR VM SECURITY (UNIFICADO) - v4 FINAL
const express = require('express');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const UserAgent = require('user-agents');
const admin = require('firebase-admin');

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 10000;
const DATA_FILE = path.join(__dirname, 'data.json');
const MONITOR_INTERVAL = parseInt(process.env.MONITOR_INTERVAL || '600000');
const MASTER_KEY = process.env.MASTER_KEY || null;

// CORS REFLEXIVO (CORRETO)
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE, PUT');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Master-Key');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

// FIREBASE
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
        const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
        if (!admin.apps.length) admin.initializeApp({ credential: admin.credential.cert(sa) });
    } catch (e) { console.error('Erro Firebase:', e.message); }
}

const client = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 20000
});

// BANCO DE DADOS JSON
let DB = { sites: [] };
function loadData() {
    if (fs.existsSync(DATA_FILE)) {
        try { DB = JSON.parse(fs.readFileSync(DATA_FILE)); } catch (e) {}
    }
}
function saveData() { fs.writeFileSync(DATA_FILE, JSON.stringify(DB, null, 2)); }
loadData();

// AUTH MIDDLEWARE
async function requireAuth(req, res, next) {
    if (!process.env.FIREBASE_SERVICE_ACCOUNT && !MASTER_KEY) return next();
    const mk = req.headers['x-master-key'] || req.headers['x-masterkey'];
    if (MASTER_KEY && mk === MASTER_KEY) return next();
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Não autorizado' });
    try {
        const token = authHeader.split(' ')[1];
        await admin.auth().verifyIdToken(token);
        next();
    } catch (e) { res.status(401).json({ error: 'Token inválido' }); }
}

// --- ROTAS UNIFICADAS ---

// ROTA DO HUNTER
app.get('/hunt', requireAuth, async (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) return res.status(400).json({ error: 'URL obrigatória' });
    try {
        const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
        const resp = await client.get(targetUrl, { headers: { 'User-Agent': ua } });
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

// ROTA DO VULNERABILITY (Melhorada para detectar Servidor e Tecnologia)
const analyzeHandler = async (req, res) => {
    const targetUrl = req.query.url || (req.body && req.body.url);
    if (!targetUrl) return res.status(400).json({ error: 'URL obrigatória' });
    try {
        const resp = await client.get(targetUrl, { validateStatus: () => true });
        const h = resp.headers || {};
        res.json({
            status: resp.status,
            server: h['server'] || 'Não detectado',
            technology: h['x-powered-by'] || h['via'] || 'Não detectada',
            securityHeaders: {
                'x-frame-options': h['x-frame-options'] || 'MISSING',
                'strict-transport-security': h['strict-transport-security'] || 'MISSING',
                'content-security-policy': h['content-security-policy'] || 'MISSING',
                'x-content-type-options': h['x-content-type-options'] || 'MISSING'
            }
        });
    } catch (e) { res.status(500).json({ error: e.message }); }
};
app.get('/analyze', requireAuth, analyzeHandler);
app.get('/api/scan', requireAuth, analyzeHandler);
app.post('/api/scan', requireAuth, analyzeHandler);

// ROTAS DO 24x7 (UPTIME)
app.get('/api/sites', requireAuth, (req, res) => {
    res.json(DB.sites.map(s => ({ id: s.id, url: s.url, name: s.name, lastCheck: s.lastCheck })));
});

app.post('/api/sites', requireAuth, async (req, res) => {
    const { url, name } = req.body;
    if (!url) return res.status(400).json({ error: 'URL obrigatória' });
    const site = { id: Date.now().toString(36), url, name: name || url, lastCheck: null };
    DB.sites.push(site);
    await checkSite(site);
    saveData();
    res.json(site);
});

// CORREÇÃO: Aceita GET e POST para check-now
const checkNowHandler = async (req, res) => {
    await runChecks();
    res.json({ ok: true, summary: DB.sites.map(s => ({ id: s.id, url: s.url, lastCheck: s.lastCheck })) });
};
app.get('/api/check-now', requireAuth, checkNowHandler);
app.post('/api/check-now', requireAuth, checkNowHandler);

// FUNÇÃO DE CHECAGEM
async function checkSite(site) {
    const start = Date.now();
    try {
        const resp = await client.get(site.url, { validateStatus: () => true });
        site.lastCheck = { at: new Date().toISOString(), up: resp.status < 400, status: resp.status, latency: Date.now() - start };
    } catch (e) {
        site.lastCheck = { at: new Date().toISOString(), up: false, error: e.message };
    }
}

async function runChecks() {
    for (const s of DB.sites) await checkSite(s);
    saveData();
}
setInterval(runChecks, MONITOR_INTERVAL);

app.get('/', (req, res) => res.json({ status: 'online' }));
app.listen(PORT, () => console.log(`🚀 Servidor na porta ${PORT}`));
