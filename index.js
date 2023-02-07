#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const httpProxy = require('http-proxy');

const config = JSON.parse(fs.readFileSync('./config.json'));

function isToken(oauth_token) {
  return oauth_token.match(/^[-_0-9A-Za-z]+$/);
}

function readToken(oauth_token) {
  try {
    if (!isToken(oauth_token)) return false;
    const file = `./tokens/${oauth_token}`;
    const json = fs.readFileSync(file);
    return JSON.parse(json);
  } catch (e) {
    return false;
  }
}

function writeToken(token) {
  const { oauth_token } = token;
  const file = `./tokens/${oauth_token}`;
  fs.writeFileSync(file, JSON.stringify(token));
}

function removeToken(token) {
  const { oauth_token } = token;
  const file = `./tokens/${oauth_token}`;
  fs.unlinkSync(file);
}

function httpsGet(url, options) {
  return new Promise((resolve) => https.get(url, options, (res) => {
    let buf = '';
    res.on('data', (chunk) => buf += chunk);
    res.on('end', () => resolve(buf));
  }));
}

function createHeaders(token) {
  const { cookies: { ct0, auth_token }, user_agent } = token;
  return {
    authorization: config.authorization,
    cookie: `ct0=${ct0}; auth_token=${auth_token}`,
    'x-csrf-token': ct0,
    'user-agent': user_agent,
  };
}

async function verifyCredentials(requestToken) {
  const { cookies: { ct0, auth_token }, user_agent } = requestToken;
  const url = 'https://api.twitter.com/1.1/account/verify_credentials.json';
  const headers = createHeaders(requestToken);
  const json = await httpsGet(url, { headers });
  return JSON.parse(json);
}

function createToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function createPin() {
  return crypto.randomInt(10000000).toString().padStart(7, '0');
}

function parseAuthorization(string = '') {
  const parsed = {};
  for (const pair of string.replace(/^\S+\s/, '').split(/,\s*/)) {
    const [key, value] = pair.split("=");
    parsed[key] = value?.slice(1, -1);
  }
  return parsed;
}

function parseCookie(string = '') {
  const parsed = {};
  for (const pair of string.split(/;\s*/)) {
    const [key, value] = pair.split("=");
    parsed[key] = value;
  }
  return parsed;
}

function createRequestToken(oauth_consumer_key) {
  const consumer = config.consumers[oauth_consumer_key];
  if (!consumer) return;
  const { oauth_callback } = consumer;
  const oauth_token = createToken();
  const oauth_token_secret = createToken();
  return {
    oauth_consumer_key,
    oauth_callback,
    oauth_callback_confirmed: true,
    oauth_token,
    oauth_token_secret,
  };
}

function createOobHtml(pin) {
  return `<!DOCTYPE html><html><body><div id="bd" role="main"><div id="oauth_pin"><p><span id="code-desc"></span><kbd aria-labelledby="code-desc"><code>${pin}</code></kbd></p></div></div></body></html>`;
}

function createCallbackUrl(requestToken) {
  const { oauth_callback, oauth_token, oauth_verifier } = requestToken;
  const location = new URL(oauth_callback);
  location.searchParams.set('oauth_token', oauth_token);
  location.searchParams.set('oauth_verifier', oauth_verifier);
  return location;
}

function createLoginUrl(token) {
  const redirect = new URL('https://api.twitter.com/oauth/authorize');
  redirect.searchParams.set('oauth_token', token);
  const location = new URL('https://twitter.com/login');
  location.searchParams.set('redirect_after_login', redirect);
  return location;
}

async function createAccessToken(requestToken) {
  const { oauth_consumer_key, cookies, user_agent } = requestToken;
  const { id, screen_name } = await verifyCredentials(requestToken);
  const oauth_token = `${id}-${createToken()}`;
  const oauth_token_secret = createToken();
  return {
    oauth_consumer_key,
    oauth_token,
    oauth_token_secret,
    cookies,
    user_agent,
    user_id: id,
    screen_name,
  }
}

function respondUrlencoded(res, obj) {
  const params = new URLSearchParams(obj);
  res.writeHead(200, { 'content-type': 'application/x-www-form-urlencoded' });
  res.end(params.toString());
}

function respondHtml(res, data) {
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(data);
}

function respondLocation(res, location) {
  res.writeHead(302, { location });
  res.end();
}

function sliceObject(obj, keys) {
  const entries = keys.map((key) => [key, obj[key]]);
  return Object.fromEntries(entries);
}

function respondRequestToken(res, requestToken) {
  respondUrlencoded(res, sliceObject(requestToken, [
    'oauth_token',
    'oauth_token_secret',
    'oauth_callback_confirmed',
  ]));
}

function respondAccessToken(res, accessToken) {
  respondUrlencoded(res, sliceObject(accessToken, [
    'oauth_token',
    'oauth_token_secret',
    'user_id',
    'screen_name',
  ]));
}

function setCookies(requestToken, headers) {
  const cookies = parseCookie(headers.cookie);
  if (cookies.auth_token && cookies.ct0) {
    requestToken.cookies = cookies;
    requestToken.user_agent = headers['user-agent'];
    return true;
  }
}

const handlers = {
  '/oauth/request_token': async ({ authorization }, url, res) => {
    const { oauth_consumer_key } = parseAuthorization(authorization);
    const requestToken = createRequestToken(oauth_consumer_key);
    if (!requestToken) throw new Error();
    writeToken(requestToken);
    respondRequestToken(res, requestToken);
  },
  '/oauth/authorize': async (headers, url, res) => {
    const oauth_token = url.searchParams.get('oauth_token');
    const requestToken = readToken(oauth_token);
    if (!requestToken) throw new Error();
    if (setCookies(requestToken, headers)) {
      if (requestToken.oauth_callback === 'oob') {
        const pin = createPin();
        requestToken.oauth_verifier = pin;
        respondHtml(res, createOobHtml(pin));
      } else {
        requestToken.oauth_verifier = createToken();
        respondLocation(res, createCallbackUrl(requestToken));
      }
      writeToken(requestToken);
    } else {
      respondLocation(res, createLoginUrl(oauth_token));
    }
  },  
  '/oauth/access_token': async ({ authorization }, url, res) => {
    const { oauth_token, oauth_verifier } = parseAuthorization(authorization);
    const requestToken = readToken(oauth_token);
    if (!requestToken) throw new Error();
    if (oauth_verifier !== requestToken.oauth_verifier) throw new Error();
    removeToken(requestToken);
    const accessToken = await createAccessToken(requestToken);
    writeToken(accessToken);
    respondAccessToken(res, accessToken)
  },
};

const proxy = httpProxy.createProxyServer({
  target: 'https://api.twitter.com',
  secure: true,
});

proxy.on('proxyReq', (proxyReq, req, res, options) => {
  const { authorization } = req.headers;
  const { oauth_consumer_key, oauth_token } = parseAuthorization(authorization);
  const accessToken = readToken(oauth_token);
  if (!accessToken) return;
  if (oauth_consumer_key !== accessToken.oauth_consumer_key) return;
  const headers = createHeaders(accessToken);
  for (const key of Object.keys(headers)) {
    proxyReq.setHeader(key, headers[key]);
  }
});

const options = {
  key: fs.readFileSync('private.key'),
  cert: fs.readFileSync('api.twitter.com.crt'),
};

const server = https.createServer(options, async (req, res) => {
  const { headers } = req;
  const url = new URL(req.url, `https://${headers.host}`);
  console.log(new Date(), JSON.stringify(headers), req.url);
  switch (headers.host) {
    case 'api.twitter.com': {
      const handler = handlers[url.pathname];
      if (handler) {
        try {
          await handler(headers, url, res);
        } catch (e) {
          res.writeHead(400);
          res.end();
        }
      } else {
        proxy.web(req, res);
      }
      break;
    }
    default: {
      res.writeHead(400);
      res.end();
    }
  }
});

server.listen(443);

