const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// In-memory storage for users and sessions. In a production system you would
// persist these to a database. This is just for demonstration.
const users = {};
// Map session tokens to usernames
const sessionTokens = {};
// Map usernames to current active session token (for single-login enforcement)
const userSessions = {};

/**
 * Helper to send an HTTP response with a given status code, headers and body.
 * @param {http.ServerResponse} res
 * @param {number} statusCode
 * @param {Object} headers
 * @param {string|Buffer} body
 */
function sendResponse(res, statusCode, headers, body) {
  res.writeHead(statusCode, headers);
  res.end(body);
}

/**
 * Parses the cookies from the request header into an object.
 * @param {http.IncomingMessage} req
 * @returns {Object}
 */
function parseCookies(req) {
  const list = {};
  const cookieHeader = req.headers.cookie;
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    const key = parts[0] && parts[0].trim();
    const value = parts[1] && parts[1].trim();
    if (key && value) {
      list[key] = decodeURIComponent(value);
    }
  });
  return list;
}

/**
 * Generates a random session token.
 * @returns {string}
 */
function generateToken() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Serves static files from the public directory.
 * Automatically infers content type from the file extension.
 * @param {http.ServerResponse} res
 * @param {string} filePath
 */
function serveStatic(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      sendResponse(res, 404, { 'Content-Type': 'text/plain' }, 'Not found');
    } else {
      const ext = path.extname(filePath).toLowerCase();
      let contentType = 'text/plain';
      if (ext === '.html') contentType = 'text/html';
      else if (ext === '.css') contentType = 'text/css';
      else if (ext === '.js') contentType = 'application/javascript';
      else if (ext === '.png') contentType = 'image/png';
      else if (ext === '.jpg' || ext === '.jpeg') contentType = 'image/jpeg';
      else if (ext === '.mp4') contentType = 'video/mp4';
      else if (ext === '.ico') contentType = 'image/x-icon';
      sendResponse(res, 200, { 'Content-Type': contentType }, data);
    }
  });
}

/**
 * Checks if the request is associated with a valid logged in session. If so,
 * returns the username; otherwise returns null.
 * @param {http.IncomingMessage} req
 */
function getLoggedInUser(req) {
  const cookies = parseCookies(req);
  const token = cookies.session;
  if (!token) return null;
  const username = sessionTokens[token];
  if (!username) return null;
  // Check that this token is still the active session for this user
  if (userSessions[username] !== token) {
    // Token is stale (another login happened)
    return null;
  }
  return username;
}

/**
 * Handler for incoming HTTP requests. Routes requests to appropriate handlers.
 */
function requestHandler(req, res) {
  const method = req.method;
  const url = req.url.split('?')[0];

  // Serve static files from the public directory
  const publicDir = path.join(__dirname, 'public');
  // If the request is for a file inside /public, handle it
  if (url.startsWith('/static/')) {
    const filePath = path.join(publicDir, url.replace('/static/', ''));
    return serveStatic(res, filePath);
  }

  // Routing logic
  if (method === 'GET' && url === '/') {
    // Home page
    return serveStatic(res, path.join(publicDir, 'home.html'));
  }
  if (method === 'GET' && url === '/login') {
    return serveStatic(res, path.join(publicDir, 'login.html'));
  }
  if (method === 'GET' && url === '/register') {
    return serveStatic(res, path.join(publicDir, 'register.html'));
  }
  if (method === 'GET' && url === '/dashboard') {
    const username = getLoggedInUser(req);
    if (!username) {
      // Redirect to login
      sendResponse(res, 302, { 'Location': '/login' }, '');
    } else {
      // Serve dashboard page
      fs.readFile(path.join(publicDir, 'dashboard.html'), 'utf8', (err, contents) => {
        if (err) {
          sendResponse(res, 500, { 'Content-Type': 'text/plain' }, 'Server error');
        } else {
          // Replace placeholder with username
          const page = contents.replace(/{{USERNAME}}/g, username);
          sendResponse(res, 200, { 'Content-Type': 'text/html' }, page);
        }
      });
    }
    return;
  }
  if (method === 'GET' && url.startsWith('/video/')) {
    const username = getLoggedInUser(req);
    if (!username) {
      sendResponse(res, 302, { 'Location': '/login' }, '');
    } else {
      // Serve video page (we only have one sample page)
      const id = url.split('/').pop();
      fs.readFile(path.join(publicDir, 'video.html'), 'utf8', (err, contents) => {
        if (err) {
          sendResponse(res, 500, { 'Content-Type': 'text/plain' }, 'Server error');
        } else {
          const page = contents.replace(/{{USERNAME}}/g, username).replace(/{{VIDEO_ID}}/g, id);
          sendResponse(res, 200, { 'Content-Type': 'text/html' }, page);
        }
      });
    }
    return;
  }
  if (method === 'GET' && url === '/logout') {
    const cookies = parseCookies(req);
    const token = cookies.session;
    if (token && sessionTokens[token]) {
      const username = sessionTokens[token];
      // Remove token from mappings
      delete sessionTokens[token];
      if (userSessions[username] === token) delete userSessions[username];
    }
    // Clear cookie
    sendResponse(res, 302, { 'Location': '/', 'Set-Cookie': 'session=; Max-Age=0; Path=/' }, '');
    return;
  }
  if (method === 'POST' && url === '/register') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const username = params.get('username');
      const password = params.get('password');
      if (!username || !password) {
        sendResponse(res, 400, { 'Content-Type': 'text/plain' }, 'Missing credentials');
        return;
      }
      if (users[username]) {
        sendResponse(res, 200, { 'Content-Type': 'text/html' }, `<p>User already exists. <a href="/login">Login here</a></p>`);
        return;
      }
      // Simple password storage (plain text). For demonstration only!
      users[username] = password;
      sendResponse(res, 302, { 'Location': '/login' }, '');
    });
    return;
  }
  if (method === 'POST' && url === '/login') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const username = params.get('username');
      const password = params.get('password');
      if (!username || !password) {
        sendResponse(res, 400, { 'Content-Type': 'text/plain' }, 'Missing credentials');
        return;
      }
      if (!users[username] || users[username] !== password) {
        sendResponse(res, 200, { 'Content-Type': 'text/html' }, `<p>Invalid credentials. <a href="/login">Try again</a></p>`);
        return;
      }
      // Create a new session token, revoke previous session
      const token = generateToken();
      // Revoke previous session if exists
      const oldToken = userSessions[username];
      if (oldToken) {
        delete sessionTokens[oldToken];
      }
      // Store new session
      userSessions[username] = token;
      sessionTokens[token] = username;
      // Set cookie
      const expiresIn = 60 * 60 * 24; // 1 day
      sendResponse(res, 302, {
        'Location': '/dashboard',
        'Set-Cookie': `session=${token}; Max-Age=${expiresIn}; HttpOnly; Path=/`
      }, '');
    });
    return;
  }
  // Default: 404
  sendResponse(res, 404, { 'Content-Type': 'text/plain' }, 'Not found');
}

const server = http.createServer(requestHandler);

const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});