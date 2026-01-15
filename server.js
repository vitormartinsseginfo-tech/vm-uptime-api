// server.js - SUPER SERVIDOR VM SECURITY (UNIFICADO)
const express = require('express');
const axios = require('axios');
const https = require('https');
const fs = require('fs');
const path = require('path');
const UserAgent = require('user-agents');
const admin = require('firebase-admin');
const { JSDOM } = require('jsdom');

const app = express();
app.use(express.json());

// ---------- CONFIGURAÇÕES ----------
const PORT = process.env.PORT || 10000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const MONITOR_INTERVAL = parseInt(process.env.MONITOR_INTERVAL || '600000'); // 10 min
const MASTER_KEY = process.env.MASTER_KEY || null; 

// ---------- CORREÇÃO DEFINITIVA DE CORS ----------
app.use((req, res, next) => {
    const origin = req.headers.origin;
    // Permite qualquer origem, mas reflete o Origin para evitar erro de "wildcard *"
    if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);
    }
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE, PUT');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Master-Key, X-Requested-With');

    // Responde imediatamente a requisições de pré-verificação (OPTIONS)
    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }
    next();
});

// Inicializa Firebase Admin
if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
        const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
        if (!admin.apps.length) {
            admin.initializeApp({ credential: admin.credential.cert(sa) });
        }
        console.log('✅ Firebase Admin inicializado');
    } catch (e) {
        console.error('❌ Erro Firebase Admin:', e.message);
    }
}

const client = axios.create({
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 20000
});

// ---------- BANCO DE DADOS SIMPLES (JSON) ----------
let DB = { sites: [] };
function loadData() {
    try {
        if (fs.existsSync(DATA_FILE)) {
            DB = JSON.parse(fs.readFileSync(DATA_FILE));
            console.log('🔁 Dados carregados de', DATA_FILE);
        }
    } catch (e) { console.error('Erro ao carregar dados:', e.message); }
}
function saveData() {
    try {
        fs.writeFileSync(DATA_FILE, JSON.stringify(DB, null, 2));
    } catch (e) { console.error('Erro ao salvar dados:', e.message); }
}
loadData();

// ---------- MIDDLEWARE DE AUTENTICAÇÃO ----------
async function requireAuth(req, res, next) {
    if (!process.env.FIREBASE_SERVICE_ACCOUNT && !MASTER_KEY) return next();
    
    const mk = req.headers['x-master-key'] || req.headers['x-masterkey'];
    if (MASTER_KEY && mk === MASTER_KEY) return next();

    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Não autorizado' });
    }
    const token = authHeader.split(' ')[1];
    try {
        await admin.auth().verifyIdToken(token);
        next();
    } catch (e) {
        res.status(401).json({ error: 'Token inválido' });
    }
}

// ---------- ROTA: CONTACT HUNTER ----------
app.get('/hunt', requireAuth, async (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) return res.status(400).json({ error: 'URL obrigatória' });
    try {
        const ua = new UserAgent({ deviceCategory: 'desktop' }).toString();
        const resp = await client.get(targetUrl, { headers: { 'User-Agent': ua } });
        let html = resp.data;
        const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
        const phoneRegex = /(?:\+?55\s?)?(?:\(?\d{2}\)?\s?)(?:9\d{4}|\d{4})[-\.\s]?\d{4}/g;
        const socialRegex = /(facebook|instagram|linkedin|twitter|wa\.me|api\.whatsapp)\.com\/[a-zA-Z0-9._\/-]+/g;
        res.json({
            emails: [...new Set(html.match(emailRegex) || [])],
            phones: [...new Set(html.match(phoneRegex) || [])],
            socials: [...new Set(html.match(socialRegex) || [])].map(s => s.startsWith('http') ? s : 'https://' + s)
        });
    } catch (e) { res.status(500).json({ error: 'Erro no Hunter', details: e.message }); }
});

// ---------- ROTA: ANALISADOR DE VULNERABILIDADES ----------
app.get('/analyze', requireAuth, async (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) return res.status(400).json({ error: 'URL obrigatória' });
    try {
        const resp = await client.get(targetUrl, { validateStatus: () => true });
        const h = resp.headers;
        res.json({
            status: resp.status,
            securityHeaders: {
                'x-frame-options': h['x-frame-options'] || 'MISSING',
                'strict-transport-security': h['strict-transport-security'] || 'MISSING',
                'content-security-policy': h['content-security-policy'] || 'MISSING',
                'x-content-type-options': h['x-content-type-options'] || 'MISSING'
            }
        });
    } catch (e) { res.status(500).json({ error: 'Erro no Scan', details: e.message }); }
});

// ---------- ROTAS: MONITORAMENTO 24x7 (UPTIME) ----------
app.get('/api/sites', requireAuth, (req, res) => {
    res.json(DB.sites.map(s => ({ id: s.id, url: s.url, name: s.name, lastCheck: s.lastCheck })));
});

app.post('/api/sites', requireAuth, (req, res) => {
    const { url, name } = req.body;
    if (!url) return res.status(400).json({ error: 'URL obrigatória' });
    const site = { id: Date.now().toString(36), url, name: name || url, history: [], lastCheck: null };
    DB.sites.push(site);
    saveData();
    res.json(site);
});

app.delete('/api/sites/:id', requireAuth, (req, res) => {
    DB.sites = DB.sites.filter(s => s.id !== req.params.id);
    saveData();
    res.json({ ok: true });
});

// Lógica de checagem automática
async function runChecks() {
    console.log('⏱️ Checando sites...');
    for (const site of DB.sites) {
        try {
            const start = Date.now();
            const resp = await client.get(site.url, { validateStatus: () => true });
            site.lastCheck = { at: new Date().toISOString(), up: resp.status < 400, status: resp.status, latency: Date.now() - start };
        } catch (e) {
            site.lastCheck = { at: new Date().toISOString(), up: false, error: e.message };
        }
    }
    saveData();
}
setInterval(runChecks, MONITOR_INTERVAL);

app.get('/', (req, res) => res.json({ status: 'online', tools: ['hunter', 'uptime', 'analyzer'] }));

app.listen(PORT, () => console.log(`🚀 Super Servidor na porta ${PORT}`));
