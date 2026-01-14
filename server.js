// server.js - VM Security Unified API (Token Edition)
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const { Pool } = require('pg');
const cookieParser = require('cookie-parser');
const { createClient } = require('@supabase/supabase-js');

const app = express();

// ========== CONFIG ==========
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const PANEL_PASSWORD = process.env.PANEL_PASSWORD || 'admin123';
const SUPABASE_URL = process.env.SUPABASE_URL || null;
const SUPABASE_KEY = process.env.SUPABASE_KEY || null;

// Supabase client
let supabase = null;
if (SUPABASE_URL && SUPABASE_KEY) {
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
}

// ========== MIDDLEWARE ==========
app.use(express.json());
app.use(cookieParser());

// CORS Habilitado para aceitar Authorization Header
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ========== DATABASE ==========
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ========== AUTH MIDDLEWARE (Híbrido: Cookie ou Token) ==========
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  // Se tiver o cookie OU o token "vm_access_granted", libera
  if ((req.cookies && req.cookies.vm_uptime_auth === 'true') || token === 'vm_access_granted') {
    return next();
  }
  return res.status(401).json({ error: 'Não autorizado' });
}

// ========== ROTA DE LOGIN (Gera Token) ==========
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const MASTER_PASSWORD = process.env.PANEL_PASSWORD || PANEL_PASSWORD;

    let authenticated = false;

    // 1. Checa Senha Mestra
    if (password && password === MASTER_PASSWORD) {
      authenticated = true;
    } 
    // 2. Checa Supabase (se enviado email)
    else if (email && password && supabase) {
      const { data, error } = await supabase.auth.signInWithPassword({ email, password });
      if (!error && data.user) authenticated = true;
    }

    if (authenticated) {
      // Define o cookie (para o Monitor antigo)
      res.cookie('vm_uptime_auth', 'true', {
        httpOnly: true, secure: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000
      });

      // Retorna o TOKEN para o Vulnerability Scanner novo
      return res.json({ 
        success: true, 
        token: 'vm_access_granted', 
        user: { email: email || 'admin@vm-security.com' } 
      });
    }

    return res.status(401).json({ error: 'Senha incorreta' });
  } catch (err) {
    console.error('Erro no login:', err);
    return res.status(500).json({ error: 'Erro interno' });
  }
});

// ========== ROTA DE SCAN (Protegida) ==========
app.get('/api/scan', requireAuth, async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ error: 'URL obrigatória' });

  const url = target.startsWith('http') ? target : `https://${target}`;
  const results = { target: url, score: 100, vulnerabilities: [], tech: {} };

  try {
    const response = await axios.get(url, { timeout: 8000, validateStatus: false, headers: { 'User-Agent': 'VM-Scanner/1.0' } });
    results.tech.server = response.headers['server'] || 'Não identificado';
    results.tech.poweredBy = response.headers['x-powered-by'] || 'Não identificado';

    // Testes de arquivos
    const tests = [
      { path: '/.env', name: 'Arquivo .env exposto', sev: 'CRITICAL' },
      { path: '/.git/config', name: 'Repositório Git exposto', sev: 'CRITICAL' },
      { path: '/wp-config.php.bak', name: 'Backup de config exposto', sev: 'HIGH' }
    ];

    for (const t of tests) {
      try {
        const c = await axios.get(`${url}${t.path}`, { timeout: 2000, validateStatus: false });
        if (c.status === 200) {
          results.vulnerabilities.push({ name: t.name, severity: t.sev, desc: `O arquivo ${t.path} foi encontrado publicamente.` });
          results.score -= 30;
        }
      } catch (e) {}
    }

    if (!response.headers['x-frame-options']) {
      results.vulnerabilities.push({ name: 'Falta de X-Frame-Options', severity: 'LOW', desc: 'Risco de Clickjacking.' });
      results.score -= 5;
    }

    results.score = Math.max(0, results.score);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: 'Erro ao acessar site: ' + err.message });
  }
});

// Rota de verificação simples
app.get('/api/auth/check', requireAuth, (req, res) => {
  res.json({ authenticated: true });
});

app.listen(PORT, () => console.log(`API rodando na porta ${PORT}`));
