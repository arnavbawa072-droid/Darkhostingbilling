require('dotenv').config();
const express      = require('express');
const nodemailer   = require('nodemailer');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path         = require('path');
const crypto       = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ── IN-MEMORY DB ──────────────────────────────────────────────────────────
const users       = new Map();
const resetTokens = new Map();

// ── PRE-CREATE ADMIN USER on startup ─────────────────────────────────────
// Admin can login directly — no need to register first
async function initAdmin() {
  const adminEmail = (process.env.ADMIN_EMAIL || '').toLowerCase();
  const adminPass  = process.env.ADMIN_PASSWORD || '';
  if (!adminEmail || !adminPass) {
    console.log('⚠️  ADMIN_EMAIL or ADMIN_PASSWORD not set in .env');
    return;
  }
  if (!users.has(adminEmail)) {
    const hash = await bcrypt.hash(adminPass, 12);
    users.set(adminEmail, {
      email: adminEmail,
      passwordHash: hash,
      createdAt: new Date(),
      isAdmin: true,
    });
    console.log('✅ Admin account ready:', adminEmail);
  }
}

// ── NODEMAILER ────────────────────────────────────────────────────────────
let transporter = null;
function getMailer() {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    });
  }
  return transporter;
}

function emailWrap(title, body) {
  return `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#04050d;font-family:'Segoe UI',sans-serif">
  <div style="max-width:520px;margin:40px auto;background:#0a0d1a;border:1px solid rgba(255,255,255,0.08);border-radius:18px;overflow:hidden">
    <div style="background:linear-gradient(135deg,#1a1a2e,#16213e);padding:28px 36px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.06)">
      <div style="font-family:'Courier New',monospace;font-size:22px;font-weight:900;letter-spacing:4px;color:#fff">⛏ DARK HOSTING</div>
      <div style="font-size:11px;color:#666;margin-top:4px;letter-spacing:2px">PREMIUM MINECRAFT HOSTING</div>
    </div>
    <div style="padding:36px">
      <h2 style="color:#f0f2ff;font-size:20px;margin:0 0 16px">${title}</h2>
      ${body}
      <div style="margin-top:32px;padding-top:20px;border-top:1px solid rgba(255,255,255,0.05);font-size:11px;color:#333;font-family:'Courier New',monospace">
        © 2025 Dark Hosting — Automated email. Do not reply.
      </div>
    </div>
  </div></body></html>`;
}

function sendMail(to, subject, html) {
  // Fire and forget — won't block response
  getMailer().sendMail({
    from: `"Dark Hosting" <${process.env.GMAIL_USER}>`,
    to, subject, html,
  }).then(() => console.log('📧 Email sent to', to))
    .catch(e => console.error('📧 Email failed:', e.message));
}

// ── REGISTER ──────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)    return res.json({ ok: false, message: 'Email and password required.' });
  if (password.length < 6)    return res.json({ ok: false, message: 'Password must be at least 6 characters.' });

  const key = email.toLowerCase();
  if (users.has(key))         return res.json({ ok: false, message: 'An account with this email already exists.' });

  const passwordHash = await bcrypt.hash(password, 12);
  users.set(key, { email: key, passwordHash, createdAt: new Date() });

  const isAdmin = key === (process.env.ADMIN_EMAIL || '').toLowerCase();
  const token   = jwt.sign({ email: key }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.cookie('dh_token', token, { httpOnly: true, maxAge: 7 * 24 * 3600 * 1000 });

  sendMail(email, 'Welcome to Dark Hosting! ⛏', emailWrap('Welcome to Dark Hosting!', `
    <p style="color:#8890b0;line-height:1.8;margin:0 0 20px">Your Dark Hosting account has been created successfully.</p>
    <p style="color:#8890b0;margin:0 0 24px">Join our Discord and create a ticket to get your server set up!</p>
    <a href="https://discord.gg/J7RGqWSU46" style="display:inline-block;padding:12px 28px;background:#5865f2;color:#fff;border-radius:10px;text-decoration:none;font-weight:700">Join Discord →</a>
  `));

  res.json({ ok: true, isAdmin });
});

// ── LOGIN ─────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.json({ ok: false, message: 'Email and password required.' });

  const key  = email.toLowerCase();
  const user = users.get(key);
  if (!user) return res.json({ ok: false, message: 'No account found with this email. Please register first.' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.json({ ok: false, message: 'Incorrect password.' });

  const isAdmin = key === (process.env.ADMIN_EMAIL || '').toLowerCase();
  const token   = jwt.sign({ email: key }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.cookie('dh_token', token, { httpOnly: true, maxAge: 7 * 24 * 3600 * 1000 });
  res.json({ ok: true, isAdmin });
});

// ── LOGOUT ────────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  res.clearCookie('dh_token');
  res.json({ ok: true });
});

// ── ME ────────────────────────────────────────────────────────────────────
app.get('/api/me', (req, res) => {
  try {
    const token   = req.cookies.dh_token;
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const isAdmin = payload.email === (process.env.ADMIN_EMAIL || '').toLowerCase();
    res.json({ ok: true, email: payload.email, isAdmin });
  } catch {
    res.json({ ok: false });
  }
});

// ── FORGOT PASSWORD ───────────────────────────────────────────────────────
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.json({ ok: false, message: 'Please enter your email address.' });

  const user = users.get(email.toLowerCase());
  if (user) {
    const token  = crypto.randomBytes(32).toString('hex');
    const expiry = Date.now() + 15 * 60 * 1000; // 15 min
    resetTokens.set(token, { email: email.toLowerCase(), expires: expiry });

    const resetUrl = `${process.env.SITE_URL}/?reset=${token}`;
    sendMail(email, 'Reset Your Dark Hosting Password', emailWrap('Password Reset Request', `
      <p style="color:#8890b0;line-height:1.8;margin:0 0 20px">We received a request to reset your password for <strong style="color:#f0f2ff">${email}</strong>.</p>
      <p style="color:#8890b0;margin:0 0 8px">This link expires in <strong style="color:#a78bfa">15 minutes</strong>.</p>
      <div style="margin:28px 0">
        <a href="${resetUrl}" style="display:inline-block;padding:14px 32px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border-radius:10px;text-decoration:none;font-weight:700;font-size:15px">Reset My Password →</a>
      </div>
      <p style="color:#333;font-size:12px">If you didn't request this, ignore this email.</p>
      <div style="margin-top:14px;padding:12px 16px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:8px">
        <p style="color:#555;font-size:11px;margin:0;word-break:break-all;font-family:'Courier New',monospace">${resetUrl}</p>
      </div>
    `));
  }

  // Always say ok so we don't leak whether email exists
  res.json({ ok: true, message: 'If an account exists with that email, a reset link has been sent.' });
});

// ── VERIFY RESET TOKEN ────────────────────────────────────────────────────
app.get('/api/verify-reset-token', (req, res) => {
  const data = resetTokens.get(req.query.token);
  if (!data || Date.now() > data.expires) return res.json({ ok: false });
  res.json({ ok: true, email: data.email });
});

// ── RESET PASSWORD ────────────────────────────────────────────────────────
app.post('/api/reset-password', async (req, res) => {
  const { token, password, confirmPassword } = req.body;
  if (!token || !password)        return res.json({ ok: false, message: 'Invalid request.' });
  if (password !== confirmPassword) return res.json({ ok: false, message: 'Passwords do not match.' });
  if (password.length < 6)        return res.json({ ok: false, message: 'Minimum 6 characters.' });

  const data = resetTokens.get(token);
  if (!data)                       return res.json({ ok: false, message: 'Invalid or already-used reset link.' });
  if (Date.now() > data.expires) {
    resetTokens.delete(token);
    return res.json({ ok: false, message: 'Reset link expired. Please request a new one.' });
  }

  const user = users.get(data.email);
  if (!user) return res.json({ ok: false, message: 'Account not found.' });

  user.passwordHash = await bcrypt.hash(password, 12);
  resetTokens.delete(token);

  sendMail(data.email, 'Password Changed — Dark Hosting', emailWrap('Password Changed Successfully', `
    <p style="color:#8890b0;line-height:1.8;margin:0 0 20px">Your Dark Hosting password has been changed successfully.</p>
    <p style="color:#8890b0;margin:0 0 24px">If you did not do this, contact us on Discord immediately.</p>
    <a href="https://discord.gg/J7RGqWSU46" style="display:inline-block;padding:12px 28px;background:#5865f2;color:#fff;border-radius:10px;text-decoration:none;font-weight:700">Contact Support →</a>
  `));

  res.json({ ok: true, message: 'Password reset! You can now sign in.' });
});

// ── SERVE ALL ROUTES → index.html ─────────────────────────────────────────
app.get('/{*path}', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── START ─────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  await initAdmin(); // pre-create admin account
  console.log(`✅ Dark Hosting running on port ${PORT}`);
});
