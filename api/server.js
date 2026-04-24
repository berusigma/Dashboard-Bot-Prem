const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
// Asumsi module lu ada di luar folder api (di root)
const { connectDB } = require('../database');
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const PremiumOrder = require('../models/PremiumOrder');
const Settings = require('../models/Settings');
const premkuSvc = require('../services/premku');
const config = require('../config');

const app = express();

// Keamanan Tingkat Dewa: Trust proxy (buat Vercel) & Rate Limiting
app.set('trust proxy', 1);
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 100, // Limit tiap IP 100 request
  message: { ok: false, message: 'Terlalu banyak request, coba lagi nanti masbro.' }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(limiter);

// Serve static dari public
app.use(express.static(path.join(__dirname, '../public')));

// ENV Variables (Pastikan diset di Vercel!)
const JWT_SECRET = process.env.JWT_SECRET || 'rahasia_negara_tingkat_dewa';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@domainlu.com';
const ADMIN_PASS = process.env.ADMIN_PASS || 'password_dashboard_lu';
const MONGO_URI = process.env.MONGO_URI; // Panggil dari Vercel ENV

// Setup Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail', // atau host SMTP lu
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS 
  }
});

// Cache OTP sementara (Di production serverless baiknya simpan di DB/Redis, 
// tapi untuk MVP ini kita simpan di memory. Vercel kadang mereset memory, 
// jadi pastikan deploy dengan region yang sama).
const otpStore = new Map();

// ─── AUTHENTICATION (EMAIL + OTP + COOKIE) ──────────────────────────────────
app.post('/api/auth/request-otp', async (req, res) => {
  const { email, password } = req.body;
  
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASS) {
    return res.status(401).json({ ok: false, message: 'Kredensial salah!' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString(); // 6 digit OTP
  otpStore.set(email, { otp, expires: Date.now() + 5 * 60000 }); // Expired 5 menit

  try {
    await transporter.sendMail({
      from: '"PremiumKita Security" <no-reply@premiumkita.com>',
      to: email,
      subject: 'Kode OTP Login Dashboard',
      html: `<h3>Sistem Keamanan Robotik Aktif</h3><p>Kode OTP lu: <b>${otp}</b></p><p>Berlaku 5 menit bro.</p>`
    });
    res.json({ ok: true, message: 'OTP dikirim ke email.' });
  } catch (error) {
    console.error('Email error:', error);
    res.status(500).json({ ok: false, message: 'Gagal kirim email OTP.' });
  }
});

app.post('/api/auth/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore.get(email);

  if (!record || record.otp !== otp || Date.now() > record.expires) {
    return res.status(401).json({ ok: false, message: 'OTP salah atau kadaluarsa.' });
  }

  otpStore.delete(email); // Hapus OTP setelah sukses

  // Buat token JWT umur 1 Jam
  const token = jwt.sign({ role: 'admin', email }, JWT_SECRET, { expiresIn: '1h' });
  
  // Set Cookie HTTPOnly biar Hacker Anti-XSS
  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000 // 1 jam
  });

  res.json({ ok: true, message: 'Login sukses, Welcome back!' });
});

// Middleware Cek Cookie JWT
function auth(req, res, next) {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ ok: false, message: 'Akses ditolak. Silakan login.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    res.clearCookie('auth_token');
    return res.status(401).json({ ok: false, message: 'Sesi habis atau tidak valid.' });
  }
}

// ─── API ROUTES (Lainnya tetap sama, tinggal pasang middleware `auth`) ─────
app.get('/api/stats', auth, async (req, res) => {
  // ... (kode query stats lu seperti sebelumnya)
  res.json({ ok: true, data: { totalUsers: 10, pendingDeposits: 2, pendingOrders: 1, totalRevenue: 50000 }}); // Contoh response
});

// Endpoint untuk Logout
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.json({ ok: true, message: 'Logout berhasil.' });
});

// ─── FRONTEND ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Connect DB (Vercel Serverless butuh koneksi di luar app.listen)
connectDB(MONGO_URI).catch(err => console.error("Gagal konek DB", err));

// HARUS EXPORT APP JIKA DI VERCEL
module.exports = app;
