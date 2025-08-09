// server.js — Node core HTTP server + Supabase auth + single-session enforcement

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3000;

// ====== ENV (set these in Render dashboard) ======
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE; // secret
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
// ================================================

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE. Set env vars in Render.');
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE);

const publicDir = path.join(__dirname, 'public');

// small helpers
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => (data += chunk));
    req.on('end', () => {
      const ct = req.headers['content-type'] || '';
      if (ct.includes('application/json')) {
        try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); }
      } else if (ct.includes('application/x-www-form-urlencoded')) {
        const obj = {};
        for (const kv of (data || '').split('&')) {
          if (!kv) continue;
          const [k, v] = kv.split('=');
          obj[decodeURIComponent(k)] = decodeURIComponent((v || '').replace(/\+/g, ' '));
        }
        resolve(obj);
      } else {
        resolve({ raw: data });
      }
    });
    req.on('error', reject);
  });
}

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`];
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  if (opts.secure !== false) parts.push('Secure');
  parts.push(`SameSite=Lax`);
  parts.push(`Path=/`);
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearCookie(res, name) {
  res.setHeader('Set-Cookie', `${name}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
}

function getCookies(req) {
  const str = req.headers.cookie || '';
  const out = {};
  str.split(';').forEach((c) => {
    const [k, v] = c.split('=');
    if (!k) return;
    out[k.trim()] = decodeURIComponent((v || '').trim());
  });
  return out;
}

function sendFile(res, filepath, status = 200, replacements = {}) {
  try {
    let html = fs.readFileSync(filepath, 'utf8');
    for (const [k, v] of Object.entries(replacements)) {
      html = html.replaceAll(k, v);
    }
    res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  } catch (e) {
    res.writeHead(404);
    res.end('Not found');
  }
}

async function verifySession(req) {
  try {
    const cookies = getCookies(req);
    const token = cookies['ssid'];
    if (!token) return null;
    const payload = jwt.verify(token, JWT_SECRET);
    const { user_id, device_id } = payload;

    const { data, error } = await supabase
      .from('sessions')
      .select('id, revoked, device_id, user_id')
      .eq('user_id', user_id)
      .eq('device_id', device_id)
      .eq('revoked', false)
      .limit(1)
      .maybeSingle();

    if (error || !data) return null;

    // touch last_seen
    await supabase
      .from('sessions')
      .update({ last_seen: new Date().toISOString() })
      .eq('id', data.id);

    return { user_id, device_id };
  } catch {
    return null;
  }
}

// Routes
async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  // static CSS
  if (pathname.startsWith('/static/')) {
    const f = path.join(publicDir, pathname.replace('/static/', ''));
    if (fs.existsSync(f)) {
      const ext = path.extname(f).toLowerCase();
      const mime = ext === '.css' ? 'text/css' : 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': mime });
      return fs.createReadStream(f).pipe(res);
    }
    res.writeHead(404); return res.end('Not found');
  }

  // Home
  if (pathname === '/' && req.method === 'GET') {
    return sendFile(res, path.join(publicDir, 'home.html'));
  }

  // Register page / POST
  if (pathname === '/register' && req.method === 'GET') {
    return sendFile(res, path.join(publicDir, 'register.html'));
  }
  if (pathname === '/register' && req.method === 'POST') {
    const body = await readBody(req);
    const email = (body.email || '').trim().toLowerCase();
    const password = (body.password || '').trim();

    if (!email || !password) {
      res.writeHead(400); return res.end('Email and password required');
    }

    // check if exists
    const exist = await supabase.from('users').select('id').eq('email', email).limit(1).maybeSingle();
    if (exist.data) {
      res.writeHead(409); return res.end('Email already registered');
    }

    const hash = bcrypt.hashSync(password, 10);
    const ins = await supabase.from('users').insert({ email, password_hash: hash }).select('id').single();
    if (ins.error) { res.writeHead(500); return res.end('Failed to register'); }

    res.writeHead(302, { Location: '/login' });
    return res.end();
  }

  // Login page / POST
  if (pathname === '/login' && req.method === 'GET') {
    return sendFile(res, path.join(publicDir, 'login.html'));
  }
  if (pathname === '/login' && req.method === 'POST') {
    const body = await readBody(req);
    const email = (body.email || '').trim().toLowerCase();
    const password = (body.password || '').trim();

    const row = await supabase
      .from('users')
      .select('id, password_hash')
      .eq('email', email)
      .limit(1)
      .maybeSingle();

    if (!row.data || !bcrypt.compareSync(password, row.data.password_hash)) {
      res.writeHead(401); return res.end('Invalid email or password');
    }

    const user_id = row.data.id;
    // revoke previous sessions
    await supabase.from('sessions').update({ revoked: true }).eq('user_id', user_id).eq('revoked', false);

    const device_id = crypto.randomUUID();
    const ua = req.headers['user-agent'] || '';
    const ip = (req.headers['x-forwarded-for'] || '').toString().split(',')[0] || req.socket.remoteAddress || '';

    const s = await supabase
      .from('sessions')
      .insert({ user_id, device_id })
      .select('id')
      .single();

    if (s.error) { res.writeHead(500); return res.end('Failed to create session'); }

    // sign JWT
    const token = jwt.sign({ user_id, device_id }, JWT_SECRET, { expiresIn: '2h' });
    setCookie(res, 'ssid', token, { httpOnly: true, secure: true, maxAge: 7200 });

    res.writeHead(302, { Location: '/dashboard' });
    return res.end();
  }

  // Logout
  if (pathname === '/logout' && req.method === 'GET') {
    const session = await verifySession(req);
    if (session) {
      await supabase
        .from('sessions')
        .update({ revoked: true })
        .eq('user_id', session.user_id)
        .eq('device_id', session.device_id)
        .eq('revoked', false);
    }
    clearCookie(res, 'ssid');
    res.writeHead(302, { Location: '/' });
    return res.end();
  }

  // Protected pages
  if (pathname === '/dashboard' && req.method === 'GET') {
    const session = await verifySession(req);
    if (!session) { res.writeHead(302, { Location: '/login' }); return res.end(); }

    // fetch email to display
    const user = await supabase.from('users').select('email').eq('id', session.user_id).single();
    const username = user.data?.email?.split('@')[0] || 'Student';
    return sendFile(res, path.join(publicDir, 'dashboard.html'), 200, { '{{USERNAME}}': username });
  }

  if (pathname === '/video' && req.method === 'GET') {
    const session = await verifySession(req);
    if (!session) { res.writeHead(302, { Location: '/login' }); return res.end(); }

    const user = await supabase.from('users').select('email').eq('id', session.user_id).single();
    const username = user.data?.email?.split('@')[0] || 'Student';
    return sendFile(res, path.join(publicDir, 'video.html'), 200, { '{{USERNAME}}': username });
  }

  // Fallback 404
  res.writeHead(404);
  res.end('Not found');
}

http.createServer((req, res) => {
  // basic security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  handle(req, res).catch((e) => {
    console.error(e);
    res.writeHead(500); res.end('Server error');
  });
}).listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
