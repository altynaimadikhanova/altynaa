import crypto from 'crypto';

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  const { hash, ...fields } = req.query;

  if (!hash) return res.status(400).json({ ok: false, error: 'hash missing' });

  const BOT_TOKEN = process.env.BOT_TOKEN;
  if (!BOT_TOKEN) {
    return res.status(200).json({ ok: true, user: fields, note: 'no token check' });
  }

  const checkString = Object.keys(fields).sort().map(k => `${k}=${fields[k]}`).join('\n');
  const secret = crypto.createHash('sha256').update(BOT_TOKEN).digest();
  const computed = crypto.createHmac('sha256', secret).update(checkString).digest('hex');

  if (computed !== hash) return res.status(403).json({ ok: false, error: 'invalid signature' });

  return res.status(200).json({ ok: true, user: fields });
}
