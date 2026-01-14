// server.js - VM Security Unified API (VERSÃO FINAL ROBUSTA)
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const { createClient } = require('@supabase/supabase-js');
const admin = require('firebase-admin');

const app = express();

// ========== CONFIG ==========
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL || null;
const PANEL_PASSWORD = process.env.PANEL_PASSWORD || 'admin123';
const SUPABASE_URL = process.env.SUPABASE_URL || null;
const SUPABASE_KEY = process.env.SUPABASE_KEY || null;
const FIREBASE_SERVICE_ACCOUNT = process.env.FIREBASE_SERVICE_ACCOUNT || null;

// ========== INICIALIZAÇÃO PROTEGIDA ==========

// 1. Supabase
let supabase = null;
try {
    if (SUPABASE_URL && SUPABASE_KEY) {
        supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
        console.log('✅ Supabase conectado.');
    }
} catch (e) { console.error('❌ Erro Supabase:', e.message); }

// 2. Firebase
let firebaseEnabled = false;
try {
    if (FIREBASE_SERVICE_ACCOUNT && !admin.apps.length) {
        const serviceAccount = JSON.parse(FIREBASE_SERVICE_ACCOUNT);
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
        firebaseEnabled = true;
        console.log('✅ Firebase Admin ativado.');
    }
} catch (e) { console.error('❌ Erro Firebase (Verifique o JSON nas variáveis de ambiente):', e.message); }

// 3. Postgres (Banco de Dados)
let pool = null;
if (DATABASE_URL) {
    pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
}

async function initDB() {
    if (!pool) return;
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS monitored_domains (
                id SERIAL PRIMARY KEY,
                url TEXT,
                domain TEXT,
                status TEXT DEFAULT 'unknown',
                response_ms INTEGER DEFAULT 0,
                last_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await pool.query(`ALTER TABLE monitored_domains ADD COLUMN IF NOT EXISTS url TEXT;`);
    } catch (e) { console.error('❌ Erro Banco de Dados:', e.message); }
}
initDB();

// ========== MIDDLEWARES ==========
app.use(express.json());
app.use(cookieParser());

app.use(cors({
    origin: [
        'https://vulnerability.vm-security.com',
        'https://dashboard.vm-security.com',
        'https://vmleakhunter.vm-security.com',
        'https://vm-security.com',
        'https://radar.vm-security.com',
        'https://24x7.vm-security.com',
        'https://www.24x7.vm-security.com'
    ],
    credentials: true
}));

// Autenticação Híbrida (Firebase + Senha Mestra)
async function requireAuth(req, res, next) {
    try {
        const authHeader = req.headers['authorization'] || '';
        const token = authHeader.replace('Bearer ', '');

        // 1. Check Senha Mestra / Cookie
        if (token === 'vm_access_granted' || req.cookies.vm_uptime_auth === 'true') {
            return next();
        }

        // 2. Check Firebase (se disponível)
        if (token && firebaseEnabled) {
            const decodedToken = await admin.auth().verifyIdToken(token);
            req.user = decodedToken;
            return next();
        }

        return res.status(401).json({ error: 'Não autorizado' });
    } catch (e) {
        return res.status(401).json({ error: 'Sessão inválida' });
    }
}

// ========== ROTAS ==========

app.get('/', (req, res) => res.send('VM Security API Online'));

// Login unificado
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (password === PANEL_PASSWORD) {
        res.cookie('vm_uptime_auth', 'true', { httpOnly: true, secure: true, sameSite: 'none', maxAge: 86400000 });
        return res.json({ success: true, token: 'vm_access_granted' });
    }
    // Tenta Supabase se email for enviado
    if (email && supabase) {
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        if (!error) return res.json({ success: true, user: data.user });
    }
    res.status(401).json({ error: 'Credenciais inválidas' });
});

// Rotas para o 24x7 (Monitoramento)
app.get('/api/sites', requireAuth, async (req, res) => {
    if (!pool) return res.json([]);
    try {
        const result = await pool.query('SELECT * FROM monitored_domains ORDER BY id DESC');
        res.json(result.rows.map(r => ({
            id: r.id,
            url: r.url || r.domain || '',
            status: r.status,
            response_ms: r.response_ms,
            last_check: r.last_check
        })));
    } catch (e) { res.json([]); }
});

app.post('/api/sites', requireAuth, async (req, res) => {
    const { url } = req.body;
    if (!pool || !url) return res.status(400).json({ error: 'Dados inválidos' });
    try {
        let target = url.trim();
        if (!/^https?:\/\//i.test(target)) target = 'https://' + target;
        await pool.query('INSERT INTO monitored_domains (url, domain) VALUES ($1, $1)', [target]);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/sites/:id', requireAuth, async (req, res) => {
    if (!pool) return res.status(500).json({ error: 'Sem banco' });
    await pool.query('DELETE FROM monitored_domains WHERE id = $1', [req.params.id]);
    res.json({ success: true });
});

// Rota do Scanner (Vulnerability)
app.get('/api/scan', requireAuth, async (req, res) => {
    const target = req.query.url;
    if (!target) return res.status(400).json({ error: 'URL ausente' });
    try {
        const response = await axios.get(target, { timeout: 10000, validateStatus: null });
        res.json({ target, status: response.status, headers: response.headers });
    } catch (e) { res.status(500).json({ error: 'Erro ao escanear' }); }
});

app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT}`));
