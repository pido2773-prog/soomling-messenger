const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Server } = require('socket.io');
const { MongoClient } = require('mongodb');

const DB_FILE = path.join(__dirname, 'db.json');
const ADMIN_PHONE = '+79996081231';
const ADMIN_PASS = '1234321';
const ELITE_PHONE = '+8888888888';
const MONGODB_URI = process.env.MONGODB_URI || '';

// ---------- persistence: MongoDB if MONGODB_URI is set, otherwise local JSON file ----------
let mongoClient = null, mongoDb = null;
const COLLECTIONS = ['users', 'messages', 'calls', 'stories'];

async function loadDB() {
  if (MONGODB_URI) {
    mongoClient = new MongoClient(MONGODB_URI);
    await mongoClient.connect();
    mongoDb = mongoClient.db('soomling');
    const data = { users: [], messages: [], calls: [], stories: [] };
    for (const col of COLLECTIONS) {
      const docs = await mongoDb.collection(col).find({}).toArray();
      data[col] = docs.map(({ _id, ...rest }) => rest);
    }
    console.log('Connected to MongoDB — data will persist across deploys.');
    return data;
  }
  console.log('MONGODB_URI not set — using local db.json (resets on every redeploy on Render free tier).');
  if (!fs.existsSync(DB_FILE)) return { users: [], messages: [], calls: [], stories: [] };
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch (e) { return { users: [], messages: [], calls: [], stories: [] }; }
}

let db = { users: [], messages: [], calls: [], stories: [] };
let saveTimer = null;
function saveDB() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    if (mongoDb) {
      for (const col of COLLECTIONS) {
        const arr = db[col];
        try {
          await mongoDb.collection(col).deleteMany({});
          if (arr.length) await mongoDb.collection(col).insertMany(arr.map(x => ({ ...x })), { ordered: false });
        } catch (e) { console.error('Mongo save error (' + col + '):', e.message); }
      }
    } else {
      fs.writeFile(DB_FILE, JSON.stringify(db), () => {});
    }
  }, 300);
}
function publicUser(u) {
  const { password, ...rest } = u;
  return rest;
}
function findUser(id) { return db.users.find(u => u.id === id); }
function findByPhone(phone) { return db.users.find(u => u.phone === phone); }
function findByUsername(username) { return db.users.find(u => u.username && u.username.toLowerCase() === username.toLowerCase()); }

async function seedAdmin() {
  let admin = findByPhone(ADMIN_PHONE);
  const hash = bcrypt.hashSync(ADMIN_PASS, 8);
  if (!admin) {
    admin = {
      id: crypto.randomUUID(), phone: ADMIN_PHONE, password: hash, username: null,
      displayName: 'Soomling', avatar: null, bio: 'Создатель Soomling Messenger',
      status: 'offline', lastSeen: Date.now(), createdAt: Date.now(),
      isAdmin: true, badge: 'creator', blocked: []
    };
    db.users.push(admin);
  } else {
    admin.password = hash; admin.isAdmin = true; admin.badge = 'creator';
  }
  const elite = findByPhone(ELITE_PHONE);
  if (elite && elite.badge !== 'creator') elite.badge = 'elite';
  saveDB();
}

async function start() {
  db = await loadDB();
  await seedAdmin();
  server.listen(process.env.PORT || 3000, () => console.log('Soomling server running on :' + (process.env.PORT || 3000)));
}

// ---------- sessions (in-memory token -> userId) ----------
const sessions = new Map();
function issueToken(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, userId);
  return token;
}
function userFromToken(token) {
  const id = sessions.get(token);
  return id ? findUser(id) : null;
}

// ---------- express app ----------
const app = express();
app.use(express.json({ limit: '15mb' })); // base64 images/voice notes
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const user = userFromToken(token);
  if (!user) return res.status(401).json({ error: 'unauthorized' });
  req.user = user;
  next();
}

app.post('/api/register', (req, res) => {
  const { phone, password, displayName } = req.body || {};
  if (!phone || !password || !displayName) return res.status(400).json({ error: 'missing_fields' });
  if (password.length < 6) return res.status(400).json({ error: 'weak_password' });
  if (findByPhone(phone)) return res.status(409).json({ error: 'phone_taken' });
  const user = {
    id: crypto.randomUUID(), phone, password: bcrypt.hashSync(password, 8), username: null,
    displayName, avatar: null, bio: '', status: 'online', lastSeen: Date.now(),
    createdAt: Date.now(), isAdmin: false, badge: phone === ELITE_PHONE ? 'elite' : null, blocked: []
  };
  db.users.push(user); saveDB();
  res.json({ token: issueToken(user.id), user: publicUser(user) });
});

app.post('/api/login', (req, res) => {
  const { phone, password } = req.body || {};
  const user = findByPhone(phone);
  if (!user || !bcrypt.compareSync(password || '', user.password)) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  res.json({ token: issueToken(user.id), user: publicUser(user) });
});

app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.get('/api/users/by-phone/:phone', auth, (req, res) => {
  const u = findByPhone(req.params.phone);
  if (!u) return res.status(404).json({ error: 'not_found' });
  res.json({ user: publicUser(u) });
});

app.get('/api/users/:id', auth, (req, res) => {
  const u = findUser(req.params.id);
  if (!u) return res.status(404).json({ error: 'not_found' });
  res.json({ user: publicUser(u) });
});

app.put('/api/profile', auth, (req, res) => {
  const { displayName, bio, avatar, username } = req.body || {};
  if (displayName) req.user.displayName = displayName.slice(0, 60);
  if (typeof bio === 'string') req.user.bio = bio.slice(0, 200);
  if (avatar) req.user.avatar = avatar;
  if (typeof username === 'string') {
    const clean = username.trim().replace(/^@/, '').slice(0, 32);
    if (clean) {
      if (!/^[a-zA-Z0-9_]{3,32}$/.test(clean)) return res.status(400).json({ error: 'bad_username' });
      const taken = findByUsername(clean);
      if (taken && taken.id !== req.user.id) return res.status(409).json({ error: 'username_taken' });
      req.user.username = clean;
    } else {
      req.user.username = null;
    }
  }
  saveDB();
  io.emit('user:update', publicUser(req.user));
  res.json({ user: publicUser(req.user) });
});

app.delete('/api/account', auth, (req, res) => {
  db.users = db.users.filter(u => u.id !== req.user.id);
  for (const [token, uid] of sessions) if (uid === req.user.id) sessions.delete(token);
  saveDB();
  res.json({ ok: true });
});

app.put('/api/block', auth, (req, res) => {
  const { userId, block } = req.body || {};
  req.user.blocked = req.user.blocked || [];
  const idx = req.user.blocked.indexOf(userId);
  if (block && idx === -1) req.user.blocked.push(userId);
  if (!block && idx > -1) req.user.blocked.splice(idx, 1);
  saveDB();
  res.json({ blocked: req.user.blocked });
});

// conversations: list of users I've exchanged messages with + last message
app.get('/api/conversations', auth, (req, res) => {
  const mine = db.messages.filter(m => m.fromUser === req.user.id || m.toUser === req.user.id);
  const partnerIds = [...new Set(mine.map(m => m.fromUser === req.user.id ? m.toUser : m.fromUser))];
  const list = partnerIds.map(id => {
    const u = findUser(id);
    if (!u) return null;
    const thread = mine.filter(m => m.fromUser === id || m.toUser === id).sort((a, b) => b.createdAt - a.createdAt);
    const unread = thread.filter(m => m.fromUser === id && m.toUser === req.user.id && !m.read).length;
    return { user: publicUser(u), lastMessage: thread[0] || null, unread };
  }).filter(Boolean);
  res.json({ conversations: list });
});

app.get('/api/messages/:peerId', auth, (req, res) => {
  const peerId = req.params.peerId;
  const thread = db.messages
    .filter(m => !m.deleted && ((m.fromUser === req.user.id && m.toUser === peerId) || (m.fromUser === peerId && m.toUser === req.user.id)))
    .sort((a, b) => a.createdAt - b.createdAt);
  const newlyRead = [];
  thread.forEach(m => { if (m.toUser === req.user.id && !m.read) { m.read = true; newlyRead.push(m.id); } });
  saveDB();
  if (newlyRead.length && peerId !== req.user.id) emitToUser(peerId, 'message:read', { ids: newlyRead, by: req.user.id });
  res.json({ messages: thread });
});

app.get('/api/calls', auth, (req, res) => {
  const mine = db.calls.filter(c => c.fromUser === req.user.id || c.toUser === req.user.id)
    .sort((a, b) => b.time - a.time);
  res.json({ calls: mine });
});

app.get('/api/stories', auth, (req, res) => {
  const now = Date.now();
  const fresh = db.stories.filter(s => now - s.createdAt < 24 * 3600 * 1000);
  res.json({ stories: fresh });
});

app.delete('/api/messages/:id', auth, (req, res) => {
  const m = db.messages.find(x => x.id === req.params.id);
  if (!m) return res.status(404).json({ error: 'not_found' });
  if (m.fromUser !== req.user.id) return res.status(403).json({ error: 'forbidden' });
  m.deleted = true; saveDB();
  const peer = m.toUser;
  emitToUser(peer, 'message:deleted', { id: m.id, peer: req.user.id });
  emitToUser(req.user.id, 'message:deleted', { id: m.id, peer });
  res.json({ ok: true });
});

// ---------- realtime ----------
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 15e6 });
const online = new Map(); // userId -> Set(socketId)

function emitToUser(userId, event, payload) {
  const sockets = online.get(userId);
  if (!sockets) return false;
  sockets.forEach(sid => io.to(sid).emit(event, payload));
  return sockets.size > 0;
}

io.on('connection', (socket) => {
  let currentUser = null;

  socket.on('auth', (token) => {
    const user = userFromToken(token);
    if (!user) return socket.emit('auth:error', 'invalid_token');
    currentUser = user;
    if (!online.has(user.id)) online.set(user.id, new Set());
    online.get(user.id).add(socket.id);
    user.status = 'online'; user.lastSeen = Date.now(); saveDB();
    io.emit('presence', { id: user.id, status: 'online' });
    socket.emit('auth:ok', publicUser(user));
  });

  socket.on('typing', (to) => { if (currentUser) emitToUser(to, 'typing', { from: currentUser.id }); });

  socket.on('message:send', (msg) => {
    if (!currentUser) return;
    if (currentUser.blocked && currentUser.blocked.includes(msg.toUser)) return;
    const target = findUser(msg.toUser);
    if (target && target.blocked && target.blocked.includes(currentUser.id)) return;
    const full = {
      id: crypto.randomUUID(), fromUser: currentUser.id, toUser: msg.toUser,
      text: (msg.text || '').slice(0, 4000), type: msg.type || 'text',
      fileData: msg.fileData || null, duration: msg.duration || null,
      createdAt: Date.now(), read: false, deleted: false
    };
    db.messages.push(full); saveDB();
    socket.emit('message:new', full);
    emitToUser(msg.toUser, 'message:new', full);
  });

  socket.on('story:new', (story) => {
    if (!currentUser) return;
    const full = {
      id: crypto.randomUUID(), userId: currentUser.id, type: story.type,
      content: story.content, createdAt: Date.now()
    };
    db.stories.push(full); saveDB();
    io.emit('story:new', full);
  });

  // WebRTC signaling relay
  ['call:invite', 'call:answer', 'call:ice', 'call:reject', 'call:end'].forEach(evt => {
    socket.on(evt, (data) => {
      if (!currentUser) return;
      data.from = currentUser.id;
      emitToUser(data.to, evt, data);
      if (evt === 'call:end' || evt === 'call:reject') {
        db.calls.push({
          id: crypto.randomUUID(), fromUser: evt === 'call:reject' ? data.to : currentUser.id,
          toUser: evt === 'call:reject' ? currentUser.id : data.to,
          type: data.callType || 'audio', time: Date.now(),
          duration: data.duration || 0, status: evt === 'call:reject' ? 'missed' : 'ended'
        });
        saveDB();
      }
    });
  });

  socket.on('disconnect', () => {
    if (!currentUser) return;
    const set = online.get(currentUser.id);
    if (set) { set.delete(socket.id); if (set.size === 0) online.delete(currentUser.id); }
    if (!online.has(currentUser.id)) {
      currentUser.status = 'offline'; currentUser.lastSeen = Date.now(); saveDB();
      io.emit('presence', { id: currentUser.id, status: 'offline' });
    }
  });
});

start();
