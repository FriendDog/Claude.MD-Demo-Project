const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again later.' },
});

const loginSchema = Joi.object({
  email: Joi.string().email().max(254).required(),
  password: Joi.string().min(8).max(128).required(),
});

// POST /auth/login
router.post('/login', loginLimiter, async (req, res) => {
  const { error, value } = loginSchema.validate(req.body, { abortEarly: false, stripUnknown: true });
  if (error) {
    return res.status(400).json({ error: 'Invalid request.' });
  }

  const { email, password } = value;

  try {
    // Parameterised query — never interpolate user input into SQL
    const result = await req.db.query(
      'SELECT id, email, password_hash, role, is_active FROM users WHERE email = $1 LIMIT 1',
      [email]
    );

    const user = result.rows[0];

    // Always run bcrypt compare to prevent timing attacks, even when user not found
    const dummyHash = '$2b$12$invalidhashpaddingtomatchbcryptlength000000000000000000000';
    const passwordMatch = await bcrypt.compare(password, user ? user.password_hash : dummyHash);

    if (!user || !passwordMatch || !user.is_active) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const token = jwt.sign(
      { sub: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '15m', algorithm: 'HS256' }
    );

    const refreshToken = jwt.sign(
      { sub: user.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d', algorithm: 'HS256' }
    );

    // Deliver refresh token via HttpOnly cookie, not response body
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({ token });
  } catch (err) {
    // Log internal error id only — no stack traces or PII to client
    const errorId = crypto.randomUUID();
    req.log.error({ errorId }, 'Login error');
    return res.status(500).json({ error: 'An unexpected error occurred.', errorId });
  }
});

module.exports = router;
