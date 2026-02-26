require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const mysql = require('mysql2');

const app = express();

// =============================
// 🔐 Gestion du secret JWT
// =============================
const SECRET = process.env.JWT_SECRET;

if (!SECRET || SECRET.length < 32) {
  console.error('JWT_SECRET must be set and at least 32 characters');
  process.exit(1);
}

// =============================
// 🛡️ Middlewares de sécurité
// =============================
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// ✅ Rate limiting login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts'
});

// ✅ Rate limiting général API
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

// =============================
// 🔐 Route login sécurisée
// =============================
app.post(
  '/api/login',
  loginLimiter,
  [
    body('username').isString().trim().notEmpty(),
    body('password').isString().notEmpty().isLength({ min: 8 })
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    if (
      username === process.env.ADMIN_USER &&
      password === process.env.ADMIN_PASS
    ) {
      const token = jwt.sign(
        { username },
        SECRET,
        { expiresIn: '1h' }
      );
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  }
);

// =============================
// ❤️ Health check
// =============================
app.get('/health', (req, res) => {
  res.json({ status: 'OK' });
});

// =============================
// 🐞 Debug uniquement hors production
// =============================
if (process.env.NODE_ENV !== 'production') {
  app.get('/debug', (req, res) => {
    res.json({ message: 'Debug mode' });
  });
}

// =============================
// 🗄️ Connexion base de données
// =============================
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "password",
  database: "testdb"
});

// =============================
// ✅ Route sécurisée (SQL paramétrée + rate limit)
// =============================
app.get('/api/user', apiLimiter, (req, res) => {
  const userId = req.query.id;

  // ✅ Requête paramétrée (empêche injection SQL)
  const query = "SELECT * FROM users WHERE id = ?";

  db.query(query, [userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(results);
  });
});

// =============================
// 🚀 Lancement serveur
// =============================
app.listen(3000, () => console.log('✅ Secure server running'));