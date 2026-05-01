// api/auth.js — Vercel Serverless Function
// Проверяет подпись Telegram и возвращает JSON с данными пользователя

import crypto from 'crypto';

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  const { hash, ...fields } = req.query;

  // ── Нет hash ─────────────────────────────────────────────────────────
  if (!hash) {
    return res.status(400).json({ ok: false, error: 'hash missing' });
  }

  // ── Нет BOT_TOKEN → режим разработки без проверки ────────────────────
  const BOT_TOKEN = process.env.BOT_TOKEN;
  if (!BOT_TOKEN) {
    console.warn('⚠️  BOT_TOKEN не задан, проверка подписи пропущена');
    return res.status(200).json({
      ok: true,
      user: fields,
      note: 'signature check skipped — set BOT_TOKEN in Vercel env vars'
    });
  }

  // ── Строка для проверки ───────────────────────────────────────────────
  const checkString = Object.keys(fields)
    .sort()
    .map(k => `${k}=${fields[k]}`)
    .join('\n');

  // ── Секретный ключ = SHA256(BOT_TOKEN) ───────────────────────────────
  const secret = crypto.createHash('sha256').update(BOT_TOKEN).digest();
  const computed = crypto.createHmac('sha256', secret).update(checkString).digest('hex');

  if (computed !== hash) {
    return res.status(403).json({ ok: false, error: 'invalid signature' });
  }

  // ── Данные устарели (>24 часов) ───────────────────────────────────────
  if (Math.floor(Date.now() / 1000) - parseInt(fields.auth_date, 10) > 86400) {
    return res.status(403).json({ ok: false, error: 'auth_date expired' });
  }

  // ── Всё ок ────────────────────────────────────────────────────────────
  console.log('✅ Вход:', fields.id, fields.username || fields.first_name);

  // Здесь можно: сохранить в БД, создать сессию, выдать JWT...
  return res.status(200).json({ ok: true, user: fields });
}
