// ========================================
// WEEK 2 - SECURITY FIXES DEMONSTRATION
// ========================================

const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const express = require('express');

const app = express();
app.use(express.json());

// ---- FIX 1: Helmet (Secure HTTP Headers) ----
app.use(helmet());
console.log('✅ FIX 1: Helmet.js applied - Secure HTTP headers enabled');

// ---- FIX 2: Input Validation & XSS Prevention ----
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!validator.isEmail(email)) {
    return res.status(400).send('❌ Invalid email format');
  }

  const cleanUsername = validator.escape(username);
  const cleanEmail = validator.normalizeEmail(email);
  console.log('✅ FIX 2: Input sanitized -', cleanUsername, cleanEmail);

  // ---- FIX 3: Password Hashing with bcrypt ----
  const hashedPassword = await bcrypt.hash(password, 10);
  console.log('✅ FIX 3: Password hashed -', hashedPassword);

  // ---- FIX 4: JWT Token Generation ----
  const token = jwt.sign({ email: cleanEmail }, 'my-secret-key-2024', { expiresIn: '1h' });
  console.log('✅ FIX 4: JWT Token created -', token);

  res.send({
    message: 'User registered securely!',
    username: cleanUsername,
    email: cleanEmail,
    hashedPassword,
    token
  });
});

app.listen(4000, () => {
  console.log('🔒 Security fixes demo running on http://localhost:4000');
});