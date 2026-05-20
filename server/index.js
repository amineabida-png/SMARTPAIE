const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const cors    = require('cors');
const compression = require('compression');
const fs      = require('fs');
const path    = require('path');

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'smartpaie_secret_2026_maroc';

// ── Data directory (Railway volume ou local) ──────────────────────────────
const DATA_DIR   = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, 'smartpaie')
  : path.join(__dirname, '../data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const TRIAL_FILE = path.join(DATA_DIR, 'trial.json');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}
function readJSON(file, def = []) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return def; }
}
function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ── Init comptes ──────────────────────────────────────────────────────────
function initUsers() {
  ensureDataDir();
  if (!fs.existsSync(USERS_FILE)) {
    const adminPass = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin2026', 10);
    const demoPass  = bcrypt.hashSync('demo2026', 10);
    saveJSON(USERS_FILE, [
      { id: 1, email: 'admin@smartpaie.ma', password: adminPass, role: 'admin', nom: 'Administrateur' },
      { id: 2, email: 'demo@smartpaie.ma',  password: demoPass,  role: 'demo',  nom: 'Compte Démo'    }
    ]);
    console.log('✅ admin@smartpaie.ma / admin2026');
    console.log('✅ demo@smartpaie.ma  / demo2026');
  }
}

// ── Système démo 24h par IP ───────────────────────────────────────────────
function getTrialData() {
  ensureDataDir();
  if (!fs.existsSync(TRIAL_FILE)) saveJSON(TRIAL_FILE, {});
  return readJSON(TRIAL_FILE, {});
}
function checkTrial(ip) {
  const data = getTrialData();
  const now  = Date.now();
  if (!data[ip]) {
    data[ip] = { start: now, expires: now + 24 * 60 * 60 * 1000 };
    saveJSON(TRIAL_FILE, data);
    return { allowed: true, remaining: 24 * 60 * 60 * 1000 };
  }
  const remaining = data[ip].expires - now;
  return { allowed: remaining > 0, remaining: Math.max(0, remaining) };
}

// ── Middleware ────────────────────────────────────────────────────────────
app.use(compression());
app.use(cors());
app.use(express.json());

// ── Auth middleware ───────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Token requis' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

// ── Routes API ────────────────────────────────────────────────────────────
// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const users = readJSON(USERS_FILE, []);
  const user  = users.find(u => u.email === email);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Identifiants incorrects' });

  // Vérif démo
  if (user.role === 'demo') {
    const ip     = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
    const trial  = checkTrial(ip);
    if (!trial.allowed) return res.status(403).json({ error: 'Période démo expirée (24h)', expired: true });
    const token  = jwt.sign({ id: user.id, email: user.email, role: 'demo', remaining: trial.remaining }, SECRET, { expiresIn: '24h' });
    return res.json({ token, role: 'demo', nom: user.nom, remaining: trial.remaining });
  }

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET, { expiresIn: '7d' });
  res.json({ token, role: user.role, nom: user.nom });
});

// Changer mot de passe (admin seulement)
app.post('/api/change-password', authMiddleware, (req, res) => {
  if (req.user.role === 'demo') return res.status(403).json({ error: 'Non disponible en mode démo' });
  const { oldPassword, newPassword } = req.body;
  const users = readJSON(USERS_FILE, []);
  const user  = users.find(u => u.id === req.user.id);
  if (!user || !bcrypt.compareSync(oldPassword, user.password))
    return res.status(400).json({ error: 'Ancien mot de passe incorrect' });
  user.password = bcrypt.hashSync(newPassword, 10);
  saveJSON(USERS_FILE, users);
  res.json({ ok: true });
});

// Status démo
app.get('/api/trial-status', (req, res) => {
  const ip    = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
  const trial = checkTrial(ip);
  res.json(trial);
});

// Verify token
app.get('/api/me', authMiddleware, (req, res) => res.json(req.user));

// ── Servir l'app HTML (SPA) ───────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../public')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));

// ── Démarrage ─────────────────────────────────────────────────────────────
initUsers();
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 SmartPAIE Pro+ démarré sur le port ${PORT}`);
  console.log(`📁 Data dir : ${DATA_DIR}`);
});
