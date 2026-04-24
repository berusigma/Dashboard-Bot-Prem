const express = require('express');
const app = express();

app.use(express.json());

// Endpoint Test
app.get('/api/test', (req, res) => {
  res.json({ ok: true, message: 'Server Vercel Berhasil Hidup Ray!' });
});

// HARUS EXPORT APP
module.exports = app;
