#!/usr/bin/env node
// GARZA OS Home MCP Server v1.1.0 - SECURED
// Personal/home automation: Beeper, Abode, UniFi, ProtonMail, Graphiti, Bible, Pushcut

const http = require('http');
const https = require('https');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const VERSION = "1.1.0";

// ============ SECURITY CONFIG ============

// API Keys - NO FALLBACKS (must be set in environment)
const API_KEY = process.env.MCP_API_KEY;
const ADMIN_KEY = process.env.MCP_ADMIN_KEY; // Optional: for sensitive operations

if (!API_KEY) {
  console.error('FATAL: MCP_API_KEY environment variable required');
  process.exit(1);
}

// Rate limiting config
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 100; // requests per window
const rateLimitMap = new Map();

// Audit log (in-memory, rotates at 1000 entries)
const auditLog = [];
const MAX_AUDIT_LOG = 1000;

// Session expiration (1 hour)
const SESSION_EXPIRY = 3600000;

// Service credentials
const BEEPER_TOKEN = process.env.BEEPER_TOKEN;
const ABODE_USER = process.env.ABODE_USER;
const ABODE_PASS = process.env.ABODE_PASS;
const UNIFI_HOST = process.env.UNIFI_HOST || '192.168.10.49';
const UNIFI_USER = process.env.UNIFI_USER;
const UNIFI_PASS = process.env.UNIFI_PASS;
const GRAPHITI_URL = process.env.GRAPHITI_URL;
const BIBLE_API_KEY = process.env.BIBLE_API_KEY;
const PUSHCUT_KEY = process.env.PUSHCUT_KEY;
const PROTON_USER = process.env.PROTON_USER;
const PROTON_PASS = process.env.PROTON_PASS;
const PROTON_BRIDGE = process.env.PROTON_BRIDGE || '127.0.0.1';

// Session storage with expiration
let abodeSession = { token: null, expires: 0 };
let unifiSession = { cookies: [], token: null, expires: 0 };

// ============ SECURITY HELPERS ============

function timingSafeEqual(a, b) {
  if (!a || !b) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) {
    // Compare against self to maintain constant time
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip) || { count: 0, resetAt: now + RATE_LIMIT_WINDOW };
  
  if (now > record.resetAt) {
    record.count = 1;
    record.resetAt = now + RATE_LIMIT_WINDOW;
  } else {
    record.count++;
  }
  
  rateLimitMap.set(ip, record);
  
  // Cleanup old entries every 100 requests
  if (rateLimitMap.size > 1000) {
    for (const [key, val] of rateLimitMap) {
      if (now > val.resetAt) rateLimitMap.delete(key);
    }
  }
  
  return record.count <= RATE_LIMIT_MAX;
}

function logAudit(action, details) {
  const entry = {
    timestamp: new Date().toISOString(),
    action,
    ...details
  };
  auditLog.push(entry);
  if (auditLog.length > MAX_AUDIT_LOG) auditLog.shift();
  console.log(`[AUDIT] ${entry.timestamp} ${action}`, JSON.stringify(details));
}

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
         req.headers['x-real-ip'] || 
         req.socket?.remoteAddress || 
         'unknown';
}

function sanitizeInput(obj, maxDepth = 5, currentDepth = 0) {
  if (currentDepth > maxDepth) return '[MAX_DEPTH]';
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') {
    // Limit string length and remove control characters
    return obj.slice(0, 10000).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
  }
  if (typeof obj === 'number' || typeof obj === 'boolean') return obj;
  if (Array.isArray(obj)) {
    return obj.slice(0, 100).map(item => sanitizeInput(item, maxDepth, currentDepth + 1));
  }
  if (typeof obj === 'object') {
    const sanitized = {};
    const keys = Object.keys(obj).slice(0, 50);
    for (const key of keys) {
      const safeKey = String(key).slice(0, 100);
      sanitized[safeKey] = sanitizeInput(obj[key], maxDepth, currentDepth + 1);
    }
    return sanitized;
  }
  return String(obj).slice(0, 1000);
}

// ============ HELPERS ============

function jsonFetch(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    
    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      rejectUnauthorized: false,
      timeout: options.timeout || 15000
    };

    const req = lib.request(reqOptions, (res) => {
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString();
        try {
          resolve({ status: res.statusCode, headers: res.headers, data: JSON.parse(body) });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, data: body });
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    if (options.body) req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
    req.end();
  });
}

// ============ BEEPER ============

async function beeperRequest(path, method = 'GET', body = null) {
  if (!BEEPER_TOKEN) throw new Error('BEEPER_TOKEN not configured');
  const res = await jsonFetch(`https://api.beeper.com/v1${path}`, {
    method,
    headers: { 'Authorization': `Bearer ${BEEPER_TOKEN}` },
    body
  });
  if (res.status >= 400) throw new Error(`Beeper error: ${res.status}`);
  return res.data;
}

const beeperTools = {
  async beeper_get_accounts() {
    return await beeperRequest('/accounts');
  },
  async beeper_search(args) {
    return await beeperRequest(`/search?q=${encodeURIComponent(args.query)}`);
  },
  async beeper_search_chats(args) {
    let url = '/chats?';
    if (args.query) url += `q=${encodeURIComponent(args.query)}&`;
    if (args.scope) url += `scope=${args.scope}&`;
    if (args.type) url += `type=${args.type}&`;
    if (args.limit) url += `limit=${args.limit}&`;
    if (args.unreadOnly) url += `unread_only=true&`;
    return await beeperRequest(url);
  },
  async beeper_search_messages(args) {
    let url = '/messages/search?';
    if (args.query) url += `q=${encodeURIComponent(args.query)}&`;
    if (args.chatIDs) url += `chat_ids=${args.chatIDs.join(',')}&`;
    if (args.limit) url += `limit=${args.limit}&`;
    if (args.dateAfter) url += `date_after=${args.dateAfter}&`;
    if (args.dateBefore) url += `date_before=${args.dateBefore}&`;
    return await beeperRequest(url);
  },
  async beeper_get_chat(args) {
    return await beeperRequest(`/chats/${args.chatID}`);
  },
  async beeper_list_messages(args) {
    let url = `/chats/${args.chatID}/messages`;
    if (args.cursor) url += `?cursor=${args.cursor}`;
    return await beeperRequest(url);
  },
  async beeper_send_message(args) {
    return await beeperRequest(`/chats/${args.chatID}/messages`, 'POST', { text: args.text });
  },
  async beeper_archive_chat(args) {
    return await beeperRequest(`/chats/${args.chatID}/archive`, 'POST', { archived: args.archived !== false });
  },
  async beeper_set_chat_reminder(args) {
    return await beeperRequest(`/chats/${args.chatID}/reminder`, 'POST', {
      remindAtMs: args.remindAtMs,
      dismissOnIncomingMessage: args.dismissOnIncomingMessage
    });
  },
  async beeper_clear_chat_reminder(args) {
    return await beeperRequest(`/chats/${args.chatID}/reminder`, 'DELETE');
  }
};

// ============ ABODE ============

async function abodeAuth() {
  const now = Date.now();
  if (abodeSession.token && now < abodeSession.expires) return abodeSession.token;
  
  if (!ABODE_USER || !ABODE_PASS) throw new Error('Abode credentials not configured');
  
  const res = await jsonFetch('https://my.goabode.com/api/auth2/login', {
    method: 'POST',
    body: { id: ABODE_USER, password: ABODE_PASS }
  });
  if (res.status !== 200) throw new Error('Abode auth failed');
  
  abodeSession = {
    token: res.data.token,
    expires: now + SESSION_EXPIRY
  };
  logAudit('abode_auth', { success: true });
  return abodeSession.token;
}

async function abodeRequest(path, method = 'GET', body = null) {
  const token = await abodeAuth();
  const res = await jsonFetch(`https://my.goabode.com/api${path}`, {
    method,
    headers: { 'Authorization': `Bearer ${token}` },
    body
  });
  if (res.status >= 400) throw new Error(`Abode error: ${res.status}`);
  return res.data;
}

const abodeTools = {
  async abode_get_mode() {
    const panel = await abodeRequest('/v1/panel');
    return { mode: panel.mode };
  },
  async abode_set_mode(args) {
    logAudit('abode_set_mode', { mode: args.mode });
    return await abodeRequest('/v1/panel/mode', 'PUT', { mode: args.mode });
  },
  async abode_list_devices() {
    return await abodeRequest('/v1/devices');
  },
  async abode_get_device(args) {
    return await abodeRequest(`/v1/devices/${args.device_id}`);
  },
  async abode_lock_device(args) {
    logAudit('abode_lock_device', { device_id: args.device_id, lock: args.lock });
    return await abodeRequest(`/v1/devices/${args.device_id}/lock`, 'PUT', { lock: args.lock });
  },
  async abode_switch_device(args) {
    logAudit('abode_switch_device', { device_id: args.device_id, on: args.on });
    return await abodeRequest(`/v1/devices/${args.device_id}/switch`, 'PUT', { on: args.on });
  },
  async abode_get_settings() {
    return await abodeRequest('/v1/panel');
  },
  async abode_list_automations() {
    return await abodeRequest('/v1/automations');
  },
  async abode_trigger_automation(args) {
    logAudit('abode_trigger_automation', { automation_id: args.automation_id });
    return await abodeRequest(`/v1/automations/${args.automation_id}/trigger`, 'POST');
  }
};

// ============ UNIFI PROTECT ============

async function unifiAuth() {
  const now = Date.now();
  if (unifiSession.token && now < unifiSession.expires) return;
  
  if (!UNIFI_USER || !UNIFI_PASS) throw new Error('UniFi credentials not configured');
  
  const res = await jsonFetch(`https://${UNIFI_HOST}/api/auth/login`, {
    method: 'POST',
    body: { username: UNIFI_USER, password: UNIFI_PASS, rememberMe: true }
  });
  if (res.status !== 200) throw new Error('UniFi auth failed');
  
  const setCookies = res.headers['set-cookie'] || [];
  unifiSession.cookies = setCookies.map(c => c.split(';')[0]);
  const tokenCookie = unifiSession.cookies.find(c => c.startsWith('TOKEN='));
  if (tokenCookie) unifiSession.token = tokenCookie.split('=')[1];
  unifiSession.expires = now + SESSION_EXPIRY;
  logAudit('unifi_auth', { success: true, host: UNIFI_HOST });
}

async function unifiRequest(path, method = 'GET', body = null) {
  await unifiAuth();
  const res = await jsonFetch(`https://${UNIFI_HOST}/proxy/protect/api${path}`, {
    method,
    headers: { 'Cookie': unifiSession.cookies.join('; ') },
    body
  });
  if (res.status >= 400) throw new Error(`UniFi error: ${res.status}`);
  return res.data;
}

const unifiTools = {
  async unifi_system_info() {
    const bootstrap = await unifiRequest('/bootstrap');
    return {
      version: bootstrap.nvr?.version,
      name: bootstrap.nvr?.name,
      uptime: bootstrap.nvr?.uptime,
      cameras: bootstrap.cameras?.length || 0,
      lights: bootstrap.lights?.length || 0,
      sensors: bootstrap.sensors?.length || 0
    };
  },
  async unifi_list_cameras() {
    const cameras = await unifiRequest('/cameras');
    return cameras.map(c => ({ id: c.id, name: c.name, type: c.type, state: c.state, isConnected: c.isConnected }));
  },
  async unifi_get_camera(args) {
    return await unifiRequest(`/cameras/${args.camera_id}`);
  },
  async unifi_get_snapshot(args) {
    await unifiAuth();
    return new Promise((resolve, reject) => {
      const req = https.request({
        hostname: UNIFI_HOST,
        port: 443,
        path: `/proxy/protect/api/cameras/${args.camera_id}/snapshot?ts=${Date.now()}&force=true`,
        method: 'GET',
        headers: { 'Cookie': unifiSession.cookies.join('; ') },
        rejectUnauthorized: false,
        timeout: 8000
      }, (res) => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          if (res.statusCode === 200) {
            const buffer = Buffer.concat(chunks);
            resolve({ camera_id: args.camera_id, size: buffer.length, base64: buffer.toString('base64') });
          } else {
            reject(new Error(`Snapshot failed: ${res.statusCode}`));
          }
        });
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      req.end();
    });
  },
  async unifi_get_events(args) {
    const now = Date.now();
    const start = now - (args.minutes_ago || 30) * 60000;
    let events = await unifiRequest(`/events?start=${start}&end=${now}`);
    if (args.limit) events = events.slice(0, args.limit);
    return events;
  },
  async unifi_list_sensors() {
    return await unifiRequest('/sensors');
  },
  async unifi_list_lights() {
    return await unifiRequest('/lights');
  },
  async unifi_set_light(args) {
    logAudit('unifi_set_light', { light_id: args.light_id, on: args.on });
    const body = { lightOnSettings: { isLedForceOn: args.on } };
    if (args.brightness !== undefined) body.lightDeviceSettings = { ledLevel: args.brightness };
    return await unifiRequest(`/lights/${args.light_id}`, 'PATCH', body);
  },
  async unifi_list_chimes() {
    return await unifiRequest('/chimes');
  },
  async unifi_play_chime(args) {
    logAudit('unifi_play_chime', { chime_id: args.chime_id });
    return await unifiRequest(`/chimes/${args.chime_id}/play`, 'POST', { volume: args.volume || 50 });
  },
  async unifi_list_liveviews() {
    return await unifiRequest('/liveviews');
  },
  async unifi_list_viewers() {
    return await unifiRequest('/viewers');
  },
  async unifi_ptz_move(args) {
    return await unifiRequest(`/cameras/${args.camera_id}/ptz/relative`, 'POST', {
      pan: args.pan || 0, tilt: args.tilt || 0, zoom: args.zoom || 0
    });
  },
  async unifi_ptz_goto_preset(args) {
    return await unifiRequest(`/cameras/${args.camera_id}/ptz/goto/${args.slot}`, 'POST');
  },
  async unifi_set_camera_led(args) {
    logAudit('unifi_set_camera_led', { camera_id: args.camera_id, enabled: args.enabled });
    return await unifiRequest(`/cameras/${args.camera_id}`, 'PATCH', { ledSettings: { isEnabled: args.enabled } });
  },
  async unifi_set_camera_mic(args) {
    logAudit('unifi_set_camera_mic', { camera_id: args.camera_id, enabled: args.enabled });
    return await unifiRequest(`/cameras/${args.camera_id}`, 'PATCH', { isMicEnabled: args.enabled });
  },
  async unifi_set_lcd_message(args) {
    logAudit('unifi_set_lcd_message', { camera_id: args.camera_id, message: args.message?.slice(0, 50) });
    return await unifiRequest(`/cameras/${args.camera_id}`, 'PATCH', {
      lcdMessage: { type: 'CUSTOM_MESSAGE', text: args.message, resetAt: args.duration ? Date.now() + args.duration : null }
    });
  },
  async unifi_health_check() {
    await unifiAuth();
    return { status: 'healthy', host: UNIFI_HOST, authenticated: !!unifiSession.token };
  }
};

// ============ GRAPHITI ============

const graphitiTools = {
  async graphiti_search(args) {
    if (!GRAPHITI_URL) throw new Error('GRAPHITI_URL not configured');
    const res = await jsonFetch(`${GRAPHITI_URL}/search`, {
      method: 'POST',
      body: { query: args.query, limit: args.limit || 10 }
    });
    return res.data;
  },
  async graphiti_get_facts(args) {
    if (!GRAPHITI_URL) throw new Error('GRAPHITI_URL not configured');
    const url = args.entity ? `${GRAPHITI_URL}/facts?entity=${encodeURIComponent(args.entity)}` : `${GRAPHITI_URL}/facts`;
    const res = await jsonFetch(url);
    return res.data;
  },
  async graphiti_add_episode(args) {
    if (!GRAPHITI_URL) throw new Error('GRAPHITI_URL not configured');
    logAudit('graphiti_add_episode', { name: args.name });
    const res = await jsonFetch(`${GRAPHITI_URL}/episodes`, {
      method: 'POST',
      body: { name: args.name, content: args.content, source: args.source || 'claude' }
    });
    return res.data;
  }
};

// ============ BIBLE ============

const bibleTools = {
  async bible_votd() {
    if (!BIBLE_API_KEY) throw new Error('BIBLE_API_KEY not configured');
    const res = await jsonFetch(`https://api.scripture.api.bible/v1/bibles/de4e12af7f28f599-01/verses-of-day`, {
      headers: { 'api-key': BIBLE_API_KEY }
    });
    return res.data;
  },
  async bible_passage(args) {
    if (!BIBLE_API_KEY) throw new Error('BIBLE_API_KEY not configured');
    const res = await jsonFetch(`https://api.scripture.api.bible/v1/bibles/de4e12af7f28f599-01/passages/${encodeURIComponent(args.reference)}`, {
      headers: { 'api-key': BIBLE_API_KEY }
    });
    return res.data;
  },
  async bible_search(args) {
    if (!BIBLE_API_KEY) throw new Error('BIBLE_API_KEY not configured');
    const res = await jsonFetch(`https://api.scripture.api.bible/v1/bibles/de4e12af7f28f599-01/search?query=${encodeURIComponent(args.query)}`, {
      headers: { 'api-key': BIBLE_API_KEY }
    });
    return res.data;
  }
};

// ============ PROTONMAIL (IMAP) ============

const Imap = require('imap');
const { simpleParser } = require('mailparser');
const nodemailer = require('nodemailer');

function getImapClient() {
  if (!PROTON_USER || !PROTON_PASS) throw new Error('ProtonMail credentials not configured');
  return new Imap({
    user: PROTON_USER,
    password: PROTON_PASS,
    host: PROTON_BRIDGE,
    port: 1143,
    tls: false,
    autotls: 'never',
    connTimeout: 10000
  });
}

const protonTools = {
  async search_protonmail(args) {
    return new Promise((resolve, reject) => {
      const imap = getImapClient();
      const results = [];
      
      imap.once('ready', () => {
        imap.openBox('INBOX', true, (err) => {
          if (err) { imap.end(); return reject(err); }
          
          const criteria = args.criteria ? args.criteria.split(' ') : ['ALL'];
          imap.search(criteria, (err, uids) => {
            if (err) { imap.end(); return reject(err); }
            
            const limited = uids.slice(-(args.limit || 10));
            if (limited.length === 0) { imap.end(); return resolve([]); }
            
            const fetch = imap.fetch(limited, { bodies: 'HEADER.FIELDS (FROM TO SUBJECT DATE)', struct: true });
            fetch.on('message', (msg, seqno) => {
              let uid, header;
              msg.on('attributes', (attrs) => { uid = attrs.uid; });
              msg.on('body', (stream) => {
                let buffer = '';
                stream.on('data', (chunk) => buffer += chunk);
                stream.on('end', () => { header = buffer; });
              });
              msg.once('end', () => { results.push({ uid, header }); });
            });
            fetch.once('end', () => { imap.end(); resolve(results); });
          });
        });
      });
      
      imap.once('error', reject);
      imap.connect();
    });
  },
  
  async read_protonmail(args) {
    return new Promise((resolve, reject) => {
      const imap = getImapClient();
      
      imap.once('ready', () => {
        imap.openBox('INBOX', true, (err) => {
          if (err) { imap.end(); return reject(err); }
          
          const fetch = imap.fetch([args.uid], { bodies: '' });
          fetch.on('message', (msg) => {
            msg.on('body', (stream) => {
              simpleParser(stream, (err, parsed) => {
                imap.end();
                if (err) return reject(err);
                resolve({
                  uid: args.uid,
                  from: parsed.from?.text,
                  to: parsed.to?.text,
                  subject: parsed.subject,
                  date: parsed.date,
                  text: parsed.text,
                  html: parsed.html
                });
              });
            });
          });
        });
      });
      
      imap.once('error', reject);
      imap.connect();
    });
  },
  
  async send_protonmail(args) {
    if (!PROTON_USER || !PROTON_PASS) throw new Error('ProtonMail credentials not configured');
    logAudit('send_protonmail', { to: args.to, subject: args.subject?.slice(0, 50) });
    
    const transporter = nodemailer.createTransport({
      host: PROTON_BRIDGE,
      port: 1025,
      secure: false,
      auth: { user: PROTON_USER, pass: PROTON_PASS }
    });
    
    const result = await transporter.sendMail({
      from: PROTON_USER,
      to: args.to,
      cc: args.cc,
      bcc: args.bcc,
      subject: args.subject,
      text: args.body
    });
    
    return { messageId: result.messageId, accepted: result.accepted };
  },
  
  async list_protonmail_folders() {
    return new Promise((resolve, reject) => {
      const imap = getImapClient();
      imap.once('ready', () => {
        imap.getBoxes((err, boxes) => {
          imap.end();
          if (err) return reject(err);
          resolve(boxes);
        });
      });
      imap.once('error', reject);
      imap.connect();
    });
  }
};

// ============ PUSHCUT ============

const pushTools = {
  async push_notify(args) {
    if (!PUSHCUT_KEY) throw new Error('PUSHCUT_KEY not configured');
    logAudit('push_notify', { title: args.title });
    const res = await jsonFetch(`https://api.pushcut.io/${PUSHCUT_KEY}/notifications/${encodeURIComponent(args.title)}`, {
      method: 'POST',
      body: {
        text: args.text,
        sound: args.sound,
        isTimeSensitive: args.isTimeSensitive
      }
    });
    return res.data;
  }
};

// ============ ADMIN TOOLS ============

const adminTools = {
  async get_audit_log(args) {
    const limit = Math.min(args.limit || 50, 200);
    return auditLog.slice(-limit);
  },
  async get_rate_limits() {
    const now = Date.now();
    const active = [];
    for (const [ip, record] of rateLimitMap) {
      if (now < record.resetAt) {
        active.push({ ip: ip.slice(0, 20) + '...', count: record.count, resetIn: Math.round((record.resetAt - now) / 1000) });
      }
    }
    return { active_limits: active.length, limits: active.slice(0, 20) };
  },
  async clear_sessions() {
    abodeSession = { token: null, expires: 0 };
    unifiSession = { cookies: [], token: null, expires: 0 };
    logAudit('clear_sessions', { success: true });
    return { cleared: true };
  }
};

// ============ TOOL REGISTRY ============

const ALL_TOOLS = {
  ...beeperTools,
  ...abodeTools,
  ...unifiTools,
  ...graphitiTools,
  ...bibleTools,
  ...protonTools,
  ...pushTools,
  
  ping() {
    return { status: 'pong', timestamp: new Date().toISOString(), version: VERSION };
  }
};

// Admin tools require admin key
const ADMIN_TOOL_NAMES = ['get_audit_log', 'get_rate_limits', 'clear_sessions'];

const TOOL_SCHEMAS = [
  // Beeper
  { name: 'beeper_get_accounts', description: 'List connected messaging accounts', inputSchema: { type: 'object', properties: {} } },
  { name: 'beeper_search', description: 'Search chats and messages', inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] } },
  { name: 'beeper_search_chats', description: 'Search chats by title or participants', inputSchema: { type: 'object', properties: { query: { type: 'string' }, scope: { type: 'string', enum: ['titles', 'participants'] }, type: { type: 'string', enum: ['single', 'group', 'any'] }, limit: { type: 'number' }, unreadOnly: { type: 'boolean' } } } },
  { name: 'beeper_search_messages', description: 'Search messages across chats', inputSchema: { type: 'object', properties: { query: { type: 'string' }, chatIDs: { type: 'array', items: { type: 'string' } }, limit: { type: 'number' }, dateAfter: { type: 'string' }, dateBefore: { type: 'string' } } } },
  { name: 'beeper_get_chat', description: 'Get chat details', inputSchema: { type: 'object', properties: { chatID: { type: 'string' } }, required: ['chatID'] } },
  { name: 'beeper_list_messages', description: 'List messages from a chat', inputSchema: { type: 'object', properties: { chatID: { type: 'string' }, cursor: { type: 'string' } }, required: ['chatID'] } },
  { name: 'beeper_send_message', description: 'Send a message', inputSchema: { type: 'object', properties: { chatID: { type: 'string' }, text: { type: 'string' } }, required: ['chatID', 'text'] } },
  { name: 'beeper_archive_chat', description: 'Archive/unarchive a chat', inputSchema: { type: 'object', properties: { chatID: { type: 'string' }, archived: { type: 'boolean' } }, required: ['chatID'] } },
  { name: 'beeper_set_chat_reminder', description: 'Set a chat reminder', inputSchema: { type: 'object', properties: { chatID: { type: 'string' }, remindAtMs: { type: 'number' }, dismissOnIncomingMessage: { type: 'boolean' } }, required: ['chatID', 'remindAtMs'] } },
  { name: 'beeper_clear_chat_reminder', description: 'Clear a chat reminder', inputSchema: { type: 'object', properties: { chatID: { type: 'string' } }, required: ['chatID'] } },
  
  // Abode
  { name: 'abode_get_mode', description: 'Get current alarm mode', inputSchema: { type: 'object', properties: {} } },
  { name: 'abode_set_mode', description: 'Set alarm mode', inputSchema: { type: 'object', properties: { mode: { type: 'string', enum: ['standby', 'home', 'away'] } }, required: ['mode'] } },
  { name: 'abode_list_devices', description: 'List all devices', inputSchema: { type: 'object', properties: {} } },
  { name: 'abode_get_device', description: 'Get device details', inputSchema: { type: 'object', properties: { device_id: { type: 'string' } }, required: ['device_id'] } },
  { name: 'abode_lock_device', description: 'Lock/unlock device', inputSchema: { type: 'object', properties: { device_id: { type: 'string' }, lock: { type: 'boolean' } }, required: ['device_id', 'lock'] } },
  { name: 'abode_switch_device', description: 'Switch device on/off', inputSchema: { type: 'object', properties: { device_id: { type: 'string' }, on: { type: 'boolean' } }, required: ['device_id', 'on'] } },
  { name: 'abode_get_settings', description: 'Get panel settings', inputSchema: { type: 'object', properties: {} } },
  { name: 'abode_list_automations', description: 'List automations', inputSchema: { type: 'object', properties: {} } },
  { name: 'abode_trigger_automation', description: 'Trigger automation', inputSchema: { type: 'object', properties: { automation_id: { type: 'string' } }, required: ['automation_id'] } },
  
  // UniFi
  { name: 'unifi_system_info', description: 'Get system info', inputSchema: { type: 'object', properties: {} } },
  { name: 'unifi_list_cameras', description: 'List all cameras', inputSchema: { type: 'object', properties: {} } },
  { name: 'unifi_get_camera', description: 'Get camera details', inputSchema: { type: 'object', properties: { camera_id: { type: 'string' } }, required: ['camera_id'] } },
  { name: 'unifi_get_snapshot', description: 'Get camera snapshot', inputSchema: { type: 'object', properties: { camera_id: { type: 'string' } }, required: ['camera_id'] } },
  { name: 'unifi_get_events', description: 'Get motion events', inputSchema: { type: 'object', properties: { minutes_ago: { type: 'number' }, limit: { type: 'number' } } } },
  { name: 'unifi_list_sensors', description: 'List sensors', inputSchema: { type: 'object', properties: {} } },
  { name: 'unifi_list_lights', description: 'List lights', inputSchema: { type: 'object', properties: {} } },
  { name: 'unifi_set_light', description: 'Control light', inputSchema: { type: 'object', properties: { light_id: { type: 'string' }, on: { type: 'boolean' }, brightness: { type: 'number' } }, required: ['light_id'] } },
  { name: 'unifi_list_chimes', description: 'List chimes', inputSchema: { type: 'object', properties: {} } },
  { name: 'unifi_play_chime', description: 'Play chime', inputSchema: { type: 'object', properties: { chime_id: { type: 'string' }, volume: { type: 'number' } }, required: ['chime_id'] } },
  { name: 'unifi_list_liveviews', description: 'List liveviews', inputSchema: { type: 'object', properties: {} } },
  { name: 'unifi_list_viewers', description: 'List viewers', inputSchema: { type: 'object', properties: {} } },
  { name: 'unifi_ptz_move', description: 'PTZ control', inputSchema: { type: 'object', properties: { camera_id: { type: 'string' }, pan: { type: 'number' }, tilt: { type: 'number' }, zoom: { type: 'number' } }, required: ['camera_id'] } },
  { name: 'unifi_ptz_goto_preset', description: 'PTZ preset', inputSchema: { type: 'object', properties: { camera_id: { type: 'string' }, slot: { type: 'number' } }, required: ['camera_id', 'slot'] } },
  { name: 'unifi_set_camera_led', description: 'Set camera LED', inputSchema: { type: 'object', properties: { camera_id: { type: 'string' }, enabled: { type: 'boolean' } }, required: ['camera_id', 'enabled'] } },
  { name: 'unifi_set_camera_mic', description: 'Set camera mic', inputSchema: { type: 'object', properties: { camera_id: { type: 'string' }, enabled: { type: 'boolean' } }, required: ['camera_id', 'enabled'] } },
  { name: 'unifi_set_lcd_message', description: 'Set doorbell LCD', inputSchema: { type: 'object', properties: { camera_id: { type: 'string' }, message: { type: 'string' }, duration: { type: 'number' } }, required: ['camera_id', 'message'] } },
  { name: 'unifi_health_check', description: 'Health check', inputSchema: { type: 'object', properties: {} } },
  
  // Graphiti
  { name: 'graphiti_search', description: 'Search knowledge graph', inputSchema: { type: 'object', properties: { query: { type: 'string' }, limit: { type: 'number' } }, required: ['query'] } },
  { name: 'graphiti_get_facts', description: 'Get facts', inputSchema: { type: 'object', properties: { entity: { type: 'string' } } } },
  { name: 'graphiti_add_episode', description: 'Add episode', inputSchema: { type: 'object', properties: { name: { type: 'string' }, content: { type: 'string' }, source: { type: 'string' } }, required: ['name', 'content'] } },
  
  // Bible
  { name: 'bible_votd', description: 'Verse of the day', inputSchema: { type: 'object', properties: {} } },
  { name: 'bible_passage', description: 'Get passage', inputSchema: { type: 'object', properties: { reference: { type: 'string' } }, required: ['reference'] } },
  { name: 'bible_search', description: 'Search Bible', inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] } },
  
  // ProtonMail
  { name: 'search_protonmail', description: 'Search inbox', inputSchema: { type: 'object', properties: { criteria: { type: 'string' }, limit: { type: 'number' } } } },
  { name: 'read_protonmail', description: 'Read email by UID', inputSchema: { type: 'object', properties: { uid: { type: 'number' } }, required: ['uid'] } },
  { name: 'send_protonmail', description: 'Send email', inputSchema: { type: 'object', properties: { to: { type: 'string' }, subject: { type: 'string' }, body: { type: 'string' }, cc: { type: 'string' }, bcc: { type: 'string' } }, required: ['to', 'subject', 'body'] } },
  { name: 'list_protonmail_folders', description: 'List folders', inputSchema: { type: 'object', properties: {} } },
  
  // Push
  { name: 'push_notify', description: 'Send push notification', inputSchema: { type: 'object', properties: { title: { type: 'string' }, text: { type: 'string' }, sound: { type: 'string' }, isTimeSensitive: { type: 'boolean' } }, required: ['title', 'text'] } },
  
  // System
  { name: 'ping', description: 'Health check', inputSchema: { type: 'object', properties: {} } },
  
  // Admin (requires admin key)
  { name: 'get_audit_log', description: '[ADMIN] Get audit log', inputSchema: { type: 'object', properties: { limit: { type: 'number' } } } },
  { name: 'get_rate_limits', description: '[ADMIN] Get rate limit status', inputSchema: { type: 'object', properties: {} } },
  { name: 'clear_sessions', description: '[ADMIN] Clear all cached sessions', inputSchema: { type: 'object', properties: {} } }
];

// ============ HTTP SERVER ============

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;
  const clientIP = getClientIP(req);

  const cors = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-API-Key'
  };

  if (req.method === 'OPTIONS') {
    res.writeHead(204, cors);
    return res.end();
  }

  // Health check (no auth, no rate limit)
  if (path === '/health' || path === '/') {
    res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ status: 'healthy', version: VERSION, tools: TOOL_SCHEMAS.length }));
  }

  // Rate limit check
  if (!checkRateLimit(clientIP)) {
    logAudit('rate_limit_exceeded', { ip: clientIP });
    res.writeHead(429, cors);
    return res.end(JSON.stringify({ error: 'Rate limit exceeded. Try again later.' }));
  }

  // Auth check with timing-safe comparison
  const providedKey = url.searchParams.get('key') || req.headers['x-api-key'];
  const isValidKey = timingSafeEqual(providedKey, API_KEY);
  const isAdminKey = ADMIN_KEY && timingSafeEqual(providedKey, ADMIN_KEY);
  
  if (!isValidKey && !isAdminKey) {
    logAudit('auth_failed', { ip: clientIP, path });
    res.writeHead(401, cors);
    return res.end(JSON.stringify({ error: 'Unauthorized' }));
  }

  // MCP endpoint
  if (path === '/sse' || path === '/mcp') {
    if (req.method !== 'POST') {
      res.writeHead(405, cors);
      return res.end(JSON.stringify({ error: 'POST required' }));
    }

    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const parsed = JSON.parse(body);
        const { method, params, id } = sanitizeInput(parsed);
        let result;

        if (method === 'initialize') {
          result = {
            protocolVersion: '2024-11-05',
            capabilities: { tools: {} },
            serverInfo: { name: 'garza-home-mcp', version: VERSION }
          };
        } else if (method === 'tools/list') {
          // Filter admin tools if not using admin key
          const tools = isAdminKey ? TOOL_SCHEMAS : TOOL_SCHEMAS.filter(t => !ADMIN_TOOL_NAMES.includes(t.name));
          result = { tools };
        } else if (method === 'tools/call') {
          const toolName = params.name;
          
          // Check admin tool access
          if (ADMIN_TOOL_NAMES.includes(toolName)) {
            if (!isAdminKey) {
              throw new Error(`Tool ${toolName} requires admin key`);
            }
            const toolFn = adminTools[toolName];
            if (!toolFn) throw new Error(`Unknown admin tool: ${toolName}`);
            const toolResult = await toolFn(sanitizeInput(params.arguments || {}));
            result = { content: [{ type: 'text', text: JSON.stringify(toolResult, null, 2) }] };
          } else {
            const toolFn = ALL_TOOLS[toolName];
            if (!toolFn) throw new Error(`Unknown tool: ${toolName}`);
            
            logAudit('tool_call', { ip: clientIP, tool: toolName });
            const toolResult = await toolFn(sanitizeInput(params.arguments || {}));
            result = { content: [{ type: 'text', text: JSON.stringify(toolResult, null, 2) }] };
          }
        } else {
          throw new Error(`Unknown method: ${method}`);
        }

        res.writeHead(200, { ...cors, 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
      } catch (e) {
        logAudit('tool_error', { ip: clientIP, error: e.message });
        res.writeHead(500, { ...cors, 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message: e.message } }));
      }
    });
    return;
  }

  res.writeHead(404, cors);
  res.end(JSON.stringify({ error: 'Not found' }));
});

server.listen(PORT, () => {
  console.log(`Garza Home MCP v${VERSION} (SECURED) listening on port ${PORT}`);
  console.log(`Tools: ${TOOL_SCHEMAS.length} (${ADMIN_TOOL_NAMES.length} admin)`);
  console.log(`Rate limit: ${RATE_LIMIT_MAX} req/${RATE_LIMIT_WINDOW/1000}s`);
});
