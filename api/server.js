const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Serve static HTML (UI Cyber Putih Biru)
app.use(express.static(path.join(__dirname, '../public')));

// ─── SAFE IMPORT BLOCK (ANTI-CRASH VERCEL) ──────────────────────────────
// Kita bungkus require pakai try-catch biar Vercel gak mati mendadak
let User, Transaction, PremiumOrder, Settings, premkuSvc, config;
let moduleError = null;

try {
  // Pastikan folder-folder ini beneran sejajar sama folder 'api' di GitHub lu
  User = require('../models/User');
  Transaction = require('../models/Transaction');
  PremiumOrder = require('../models/PremiumOrder');
  Settings = require('../models/Settings');
  
  // Kalau lu belum bikin file config/premku, comment dulu biar gak error
  // premkuSvc = require('../services/premku'); 
  // config = require('../config');
} catch (err) {
  moduleError = err.message;
  console.error("🚨 Ada file module yang kurang:", moduleError);
}

// ─── ENV VARIABLES (Ambil dari Vercel Settings) ──────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'rahasia_premiumkita_dewa';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@domainlu.com';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS 
  }
});
const otpStore = new Map();

// ─── DEBUGGING ROUTE (Cek Penyakit) ──────────────────────────────────────
app.get('/api/debug', (req, res) => {
  res.json({
    status: "🔥 Server PremiumKita Hidup!",
    database: process.env.MONGO_URI ? "URL MongoDB Tersedia" : "KOSONG (Cek Vercel ENV)",
    moduleStatus: moduleError ? `Error: ${moduleError}` : "Semua file model lengkap!"
  });
});

// ─── AUTHENTICATION (EMAIL + OTP + COOKIE) ──────────────────────────────────
app.post('/api/auth/request-otp', async (req, res) => {
  const { email, password } = req.body;
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASS) {
    return res.status(401).json({ ok: false, message: 'Kredensial salah bro!' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore.set(email, { otp, expires: Date.now() + 5 * 60000 });

  try {
    await transporter.sendMail({
      from: '"System Security" <no-reply@premiumkita.com>',
      to: email,
      subject: 'Kode OTP Dashboard',
      html: `<h3>Sistem Keamanan Aktif</h3><p>Kode OTP lu: <b style="font-size:24px; color:#0ea5e9;">${otp}</b></p><p>Berlaku 5 menit.</p>`
    });
    res.json({ ok: true, message: 'OTP dikirim ke email.' });
  } catch (error) {
    res.status(500).json({ ok: false, message: 'Gagal kirim email OTP. Cek config SMTP.' });
  }
});

app.post('/api/auth/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore.get(email);

  if (!record || record.otp !== otp || Date.now() > record.expires) {
    return res.status(401).json({ ok: false, message: 'OTP salah atau kadaluarsa.' });
  }

  otpStore.delete(email); 
  const token = jwt.sign({ role: 'admin', email }, JWT_SECRET, { expiresIn: '1h' });
  
  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000
  });

  res.json({ ok: true, message: 'Login sukses!' });
});

function auth(req, res, next) {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ ok: false, message: 'Akses ditolak.' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.clearCookie('auth_token');
    return res.status(401).json({ ok: false, message: 'Sesi habis.' });
  }
}

// ─── API ROUTES (Contoh Statistik) ──────────────────────────────────────────
app.get('/api/stats', auth, async (req, res) => {
  if (moduleError) {
    return res.status(500).json({ ok: false, message: `Gagal jalankan API. Model error: ${moduleError}` });
  }

  try {
    const totalUsers = await User.countDocuments();
    // Sisanya tinggal panggil model lu di sini...
    res.json({ ok: true, data: { totalUsers, pendingDeposits: 0, pendingOrders: 0, totalRevenue: 0 }});
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ─── SERVERLESS MONGODB CONNECTION & EXPORT ─────────────────────────────────
let isConnected = false;

const handler = async (req, res) => {
  // Cegah koneksi berulang yang bikin timeout
  if (!isConnected && process.env.MONGO_URI) {
    try {
      console.log("Mencoba konek ke MongoDB...");
      await mongoose.connect(process.env.MONGO_URI, {
        serverSelectionTimeoutMS: 5000, 
      });
      isConnected = true;
      console.log("MongoDB Berhasil Konek!");
    } catch (error) {
      console.error("Gagal konek MongoDB:", error);
    }
  }
  
  return app(req, res);
};

module.exports = handler;
