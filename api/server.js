const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');

// PASTIKAN SEMUA FILE INI ADA DI FOLDER LU!
// Kalo salah satu file ini nggak ada atau nggak ke-push ke GitHub, Vercel bakal langsung Error 500.
const User = require('../models/User');
const Transaction = require('../models/Transaction');
const PremiumOrder = require('../models/PremiumOrder');
const Settings = require('../models/Settings');
const premkuSvc = require('../services/premku');
const config = require('../config');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Serve static HTML (Dashboard Cyber Putih Biru lu)
app.use(express.static(path.join(__dirname, '../public')));

// ENV Variables - WAJIB ADA DI SETTINGS VERCEL
const JWT_SECRET = process.env.JWT_SECRET || 'premiumkita_secret_dewa';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@premiumkita.com';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

// Setup Nodemailer buat OTP
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS 
  }
});

// Cache OTP di memory (Bisa di-upgrade ke DB buat next step)
const otpStore = new Map();

// ─── AUTHENTICATION (EMAIL + OTP + COOKIE) ──────────────────────────────────
app.post('/api/auth/request-otp', async (req, res) => {
  const { email, password } = req.body;
  
  if (email !== ADMIN_EMAIL || password !== ADMIN_PASS) {
    return res.status(401).json({ ok: false, message: 'Kredensial salah bro!' });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore.set(email, { otp, expires: Date.now() + 5 * 60000 }); // Expired 5 menit

  try {
    await transporter.sendMail({
      from: '"System Security" <no-reply@premiumkita.com>',
      to: email,
      subject: 'Kode OTP Dashboard PremiumKita',
      html: `<h3>Sistem Keamanan Aktif</h3><p>Kode OTP lu: <b style="font-size:24px; color:#0ea5e9;">${otp}</b></p><p>Berlaku 5 menit.</p>`
    });
    res.json({ ok: true, message: 'OTP dikirim ke email.' });
  } catch (error) {
    console.error('Email error:', error);
    res.status(500).json({ ok: false, message: 'Gagal kirim email OTP. Cek config SMTP lu.' });
  }
});

app.post('/api/auth/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore.get(email);

  if (!record || record.otp !== otp || Date.now() > record.expires) {
    return res.status(401).json({ ok: false, message: 'OTP salah atau udah kadaluarsa.' });
  }

  otpStore.delete(email); 

  const token = jwt.sign({ role: 'admin', email }, JWT_SECRET, { expiresIn: '1h' });
  
  res.cookie('auth_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000 // 1 jam
  });

  res.json({ ok: true, message: 'Login sukses!' });
});

// Middleware JWT Auth
function auth(req, res, next) {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ ok: false, message: 'Akses ditolak.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    res.clearCookie('auth_token');
    return res.status(401).json({ ok: false, message: 'Sesi habis, login lagi ya.' });
  }
}

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.json({ ok: true, message: 'Logout berhasil.' });
});

// ─── API ROUTES ─────────────────────────────────────────────────────────────
app.get('/api/stats', auth, async (req, res) => {
  try {
    const [totalUsers, pendingDeposits, pendingOrders, revenueData] = await Promise.all([
      User.countDocuments(),
      Transaction.countDocuments({ status: 'pending' }),
      PremiumOrder.countDocuments({ status: 'pending' }),
      Transaction.aggregate([
        { $match: { status: 'success' } },
        { $group: { _id: null, total: { $sum: '$amountReal' } } },
      ]),
    ]);
    res.json({
      ok: true,
      data: {
        totalUsers,
        pendingDeposits,
        pendingOrders,
        totalRevenue: revenueData[0]?.total || 0,
      },
    });
  } catch (err) {
    res.status(500).json({ ok: false, message: 'Gagal mengambil statistik DB.' });
  }
});

// Tambahin route /api/users, /api/transactions dll lu di sini dengan format yang sama pakai middleware `auth`...

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// ─── GLOBAL ERROR HANDLER BIAR GAK 500 BLANK ────────────────────────────────
app.use((err, req, res, next) => {
  console.error("Global Error:", err.message);
  res.status(500).json({ ok: false, message: 'Terjadi kesalahan di server: ' + err.message });
});

// ─── SERVERLESS MONGODB CONNECTION HANDLER ──────────────────────────────────
// Ini kunci utamanya biar Vercel nggak crash!
let isConnected = false;

module.exports = async (req, res) => {
  // Cegah koneksi berulang yang bikin timeout di Vercel
  if (!isConnected) {
    try {
      console.log("Mencoba konek ke MongoDB...");
      await mongoose.connect(process.env.MONGO_URI, {
        serverSelectionTimeoutMS: 5000, // Langsung gagal kalau 5 detik gak konek (biar gak nge-hang)
      });
      isConnected = true;
      console.log("MongoDB Berhasil Konek!");
    } catch (error) {
      console.error("Gagal konek MongoDB:", error);
      // Kasih respon jelas kalau DB yang bermasalah, bukan kodenya
      return res.status(500).json({ 
        ok: false, 
        message: 'Koneksi Database Gagal. Pastikan MONGO_URI benar dan IP 0.0.0.0/0 sudah di-allow di MongoDB Atlas.' 
      });
    }
  }
  
  // Lanjutin request ke Express app
  return app(req, res);
};
