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

// Serve static HTML
app.use(express.static(path.join(__dirname, '../public')));

// ─── SAFE IMPORT BLOCK (ANTI-CRASH VERCEL) ──────────────────────────────
let User, Transaction, PremiumOrder, Settings, premkuSvc, config;
let moduleError = null;

try {
  User = require('../models/User');
  Transaction = require('../models/Transaction');
  PremiumOrder = require('../models/PremiumOrder');
  Settings = require('../models/Settings');
  premkuSvc = require('../services/premku'); 
  config = require('../config');
} catch (err) {
  moduleError = err.message;
  console.error("🚨 Model belum lengkap:", moduleError);
}

// ─── ENV VARIABLES (Dari Vercel Settings) ──────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'rahasia_premiumkita_dewa';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@domainlu.com';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});
const otpStore = new Map();

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
      from: '"PremiumKita Security" <no-reply@premiumkita.com>',
      to: email,
      subject: 'Kode OTP Dashboard',
      html: `<h3>Sistem Keamanan Aktif</h3><p>Kode OTP lu: <b style="font-size:24px; color:#0ea5e9;">${otp}</b></p><p>Berlaku 5 menit.</p>`
    });
    res.json({ ok: true, message: 'OTP dikirim ke email.' });
  } catch (error) {
    res.status(500).json({ ok: false, message: 'Gagal kirim email OTP.' });
  }
});

app.post('/api/auth/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore.get(email);

  if (!record || record.otp !== otp || Date.now() > record.expires) {
    return res.status(401).json({ ok: false, message: 'OTP salah atau kadaluarsa.' });
  }

  otpStore.delete(email); 
  const token = jwt.sign({ role: 'admin', email }, JWT_SECRET, { expiresIn: '2h' });
  
  res.cookie('auth_token', token, {
    httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 7200000
  });
  res.json({ ok: true, message: 'Login sukses!' });
});

// Middleware Cek Login
function auth(req, res, next) {
  const token = req.cookies.auth_token;
  if (!token) return res.status(401).json({ ok: false, message: 'Akses ditolak.' });
  try {
    req.admin = jwt.verify(token, JWT_SECRET);
    if (moduleError) return res.status(500).json({ ok: false, message: `Model Error: ${moduleError}` });
    next();
  } catch (err) {
    res.clearCookie('auth_token');
    return res.status(401).json({ ok: false, message: 'Sesi habis.' });
  }
}

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('auth_token');
  res.json({ ok: true, message: 'Logout berhasil.' });
});

// ─── API FITUR UTAMA (Dari Kode Lama Lu) ────────────────────────────────────

// 1. STATS
app.get('/api/stats', auth, async (req, res) => {
  try {
    const [totalUsers, pendingDeposits, pendingOrders, totalRevenue] = await Promise.all([
      User.countDocuments(),
      Transaction.countDocuments({ status: 'pending' }),
      PremiumOrder.countDocuments({ status: 'pending' }),
      Transaction.aggregate([{ $match: { status: 'success' } }, { $group: { _id: null, total: { $sum: '$amountReal' } } }]),
    ]);
    res.json({ ok: true, data: { totalUsers, pendingDeposits, pendingOrders, totalRevenue: totalRevenue[0]?.total || 0 } });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
});

// 2. USERS
app.get('/api/users', auth, async (req, res) => {
  try {
    const users = await User.find().sort({ createdAt: -1 }).limit(100).lean();
    res.json({ ok: true, data: users });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
});

app.patch('/api/users/:number', auth, async (req, res) => {
  const { balance_prem, balance_nokos, balance_smm } = req.body;
  const update = {};
  if (balance_prem !== undefined) update.balance_prem = Number(balance_prem);
  if (balance_nokos !== undefined) update.balance_nokos = Number(balance_nokos);
  if (balance_smm !== undefined) update.balance_smm = Number(balance_smm);
  try {
    const user = await User.findOneAndUpdate({ number: req.params.number }, update, { new: true });
    res.json({ ok: true, data: user });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
});

// 3. TRANSACTIONS & DEPOSIT CONFIRMATION
app.get('/api/transactions', auth, async (req, res) => {
  try {
    const txs = await Transaction.find().sort({ createdAt: -1 }).limit(100).lean();
    res.json({ ok: true, data: txs });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
});

app.post('/api/transactions/:invoice/confirm', auth, async (req, res) => {
  try {
    const trx = await Transaction.findOne({ invoice: req.params.invoice });
    if (!trx) return res.status(404).json({ ok: false, message: 'Not found' });
    if (trx.status !== 'pending') return res.status(400).json({ ok: false, message: 'Bukan pending' });

    const { addBalance } = require('../helpers/user'); // Pastikan file helpers/user.js ada!
    await addBalance(trx.buyer, trx.wallet, trx.amountReal);
    await Transaction.updateOne({ invoice: req.params.invoice }, { status: 'success' });
    res.json({ ok: true, message: 'Deposit dikonfirmasi, saldo ditambahkan.' });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
});

// 4. ORDERS
app.get('/api/premium-orders', auth, async (req, res) => {
  try {
    const orders = await PremiumOrder.find().sort({ createdAt: -1 }).limit(100).lean();
    res.json({ ok: true, data: orders });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
});

// 5. SETTINGS & PRICING
app.get('/api/settings', auth, async (req, res) => {
  try {
    const [premkuApiKey, premkuPricing, rumahOtpKey, nokosMarkup] = await Promise.all([
      Settings.get('premku_api_key', config.premku?.api_key || ''),
      Settings.get('premku_pricing', {}),
      Settings.get('rumahotp_api_key', config.rumahotp?.apikey || ''),
      Settings.get('nokos_markup', config.nokos_markup || 0),
    ]);
    res.json({ ok: true, data: { premkuApiKey, premkuPricing, rumahOtpKey, nokosMarkup } });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
});

app.post('/api/settings/premku-pricing', auth, async (req, res) => {
  const { productId, price } = req.body;
  if (!productId) return res.status(400).json({ ok: false, message: 'productId wajib' });
  try {
    const existing = await Settings.get('premku_pricing', {});
    if (price === null || price === '' || price === 0) delete existing[String(productId)];
    else existing[String(productId)] = Number(price);
    await Settings.set('premku_pricing', existing);
    res.json({ ok: true, message: 'Harga diperbarui.', data: existing });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
});

app.get('/api/premku-products', auth, async (req, res) => {
  try {
    const data = await premkuSvc.getProducts();
    res.json({ ok: data.success, data: data.products || [] });
  } catch (err) { res.status(500).json({ ok: false, message: err.message }); }
});

// Tangkap semua UI ke index.html
app.get('/', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));

// ─── SERVERLESS MONGODB CONNECTION ──────────────────────────────────────────
let isConnected = false;
module.exports = async (req, res) => {
  if (!isConnected && process.env.MONGO_URI) {
    try {
      await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 5000 });
      isConnected = true;
    } catch (error) { console.error("DB Error:", error); }
  }
  return app(req, res);
};
