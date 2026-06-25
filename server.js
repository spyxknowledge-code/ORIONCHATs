const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const cors = require('cors');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// ----- EXPLICIT ROOT ROUTE (fix for "Not Found") -----
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ---------- Database ----------
const db = new sqlite3.Database('./chat.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT,
    salt TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER,
    expires_at INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT UNIQUE,
    password_hash TEXT,
    salt TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS room_members (
    user_id INTEGER,
    room_id INTEGER,
    PRIMARY KEY (user_id, room_id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id INTEGER,
    sender_id INTEGER,
    encrypted_content TEXT,
    iv TEXT,
    salt TEXT,
    sent_at INTEGER,
    is_deleted INTEGER DEFAULT 0
  )`);
});

// ---------- Helper ----------
const getUserId = (token) => {
  return new Promise((resolve) => {
    if (!token) return resolve(null);
    db.get('SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?', [token, Date.now()], (err, row) => {
      if (err || !row) resolve(null);
      else resolve(row.user_id);
    });
  });
};

// ---------- Auth ----------
app.post('/api/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
    if (row) return res.status(409).json({ error: 'Username taken' });
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password + salt, 10);
    db.run('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)', [username, hash, salt], function(err) {
      if (err) return res.status(500).json({ error: 'DB error' });
      const userId = this.lastID;
      const token = uuidv4();
      db.run('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)', [token, userId, Date.now() + 7*24*60*60*1000]);
      res.json({ token, username, userId });
    });
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
  db.get('SELECT id, username, password_hash, salt FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!bcrypt.compareSync(password + user.salt, user.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });
    const token = uuidv4();
    db.run('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)', [token, user.id, Date.now() + 7*24*60*60*1000]);
    res.json({ token, username: user.username, userId: user.id });
  });
});

app.post('/api/logout', async (req, res) => {
  const { token } = req.body;
  if (token) db.run('DELETE FROM sessions WHERE token = ?', [token]);
  res.json({ success: true });
});

// ---------- Rooms ----------
app.post('/api/create-room', async (req, res) => {
  const { token, roomId, password } = req.body;
  const authHeader = req.headers.authorization;
  const finalToken = token || (authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null);
  const userId = await getUserId(finalToken);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  if (!roomId || !password) return res.status(400).json({ error: 'Room ID and password required' });
  db.get('SELECT id FROM rooms WHERE room_id = ?', [roomId], (err, row) => {
    if (row) return res.status(409).json({ error: 'Room exists' });
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = bcrypt.hashSync(password + salt, 10);
    db.run('INSERT INTO rooms (room_id, password_hash, salt) VALUES (?, ?, ?)', [roomId, hash, salt], function(err) {
      if (err) return res.status(500).json({ error: 'DB error' });
      const roomDbId = this.lastID;
      db.run('INSERT INTO room_members (user_id, room_id) VALUES (?, ?)', [userId, roomDbId]);
      res.json({ success: true, roomId, salt });
    });
  });
});

app.post('/api/join-room', async (req, res) => {
  const { token, roomId, password } = req.body;
  const authHeader = req.headers.authorization;
  const finalToken = token || (authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null);
  const userId = await getUserId(finalToken);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  if (!roomId || !password) return res.status(400).json({ error: 'Room ID and password required' });
  db.get('SELECT id, password_hash, salt FROM rooms WHERE room_id = ?', [roomId], (err, row) => {
    if (!row) return res.status(404).json({ error: 'Room not found' });
    if (!bcrypt.compareSync(password + row.salt, row.password_hash)) return res.status(401).json({ error: 'Wrong password' });
    db.run('INSERT OR IGNORE INTO room_members (user_id, room_id) VALUES (?, ?)', [userId, row.id]);
    res.json({ success: true, roomId, salt: row.salt });
  });
});

app.get('/api/rooms/:roomId/messages', async (req, res) => {
  const roomId = req.params.roomId;
  const token = req.headers.authorization?.split(' ')[1];
  const userId = await getUserId(token);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  db.get('SELECT id FROM rooms WHERE room_id = ?', [roomId], (err, roomRow) => {
    if (!roomRow) return res.status(404).json({ error: 'Room not found' });
    db.all(
      `SELECT m.*, u.username as sender_name FROM messages m JOIN users u ON m.sender_id = u.id WHERE m.room_id = ? AND m.is_deleted = 0 ORDER BY m.sent_at ASC`,
      [roomRow.id],
      (err, rows) => res.json(rows)
    );
  });
});

// ---------- Socket.IO ----------
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  db.get('SELECT user_id FROM sessions WHERE token = ? AND expires_at > ?', [token, Date.now()], (err, row) => {
    if (err || !row) return next(new Error('Invalid token'));
    socket.data.userId = row.user_id;
    next();
  });
});

io.on('connection', (socket) => {
  const userId = socket.data.userId;
  if (!userId) return socket.disconnect();

  db.get('SELECT username FROM users WHERE id = ?', [userId], (err, row) => {
    socket.data.username = row ? row.username : 'User';
    console.log(`✅ ${socket.data.username} connected`);
  });

  socket.on('join-room', ({ roomId }) => {
    db.get('SELECT id FROM rooms WHERE room_id = ?', [roomId], (err, roomRow) => {
      if (!roomRow) { socket.emit('error', 'Room not found'); return; }
      db.get('SELECT user_id FROM room_members WHERE user_id = ? AND room_id = ?', [userId, roomRow.id], (err, member) => {
        if (!member) { socket.emit('error', 'Not a member'); return; }
        socket.join(roomId);
        socket.data.currentRoom = roomId;
        socket.emit('room-joined', { roomId, success: true });
        socket.to(roomId).emit('user-joined', { username: socket.data.username });
        const count = io.sockets.adapter.rooms.get(roomId)?.size || 0;
        io.to(roomId).emit('room-users', { count });
      });
    });
  });

  socket.on('typing', ({ roomId, isTyping }) => {
    socket.to(roomId).emit('typing', { username: socket.data.username, isTyping });
  });

  socket.on('room-message', async ({ roomId, encrypted_content, iv, salt, sentAt }) => {
    db.get('SELECT id FROM rooms WHERE room_id = ?', [roomId], (err, roomRow) => {
      if (!roomRow) { socket.emit('error', 'Room not found'); return; }
      db.run(
        `INSERT INTO messages (room_id, sender_id, encrypted_content, iv, salt, sent_at) VALUES (?, ?, ?, ?, ?, ?)`,
        [roomRow.id, userId, encrypted_content, iv, salt, sentAt],
        function(err) {
          if (err) { console.error(err); return; }
          const msgId = this.lastID;
          io.to(roomId).emit('new-message', {
            id: msgId,
            senderId: userId,
            sender_name: socket.data.username,
            encrypted_content,
            iv,
            salt,
            sent_at: new Date(sentAt).toISOString()
          });
        }
      );
    });
  });

  socket.on('edit-message', async ({ messageId, roomId, encrypted_content, iv, salt }) => {
    db.run(
      `UPDATE messages SET encrypted_content = ?, iv = ?, salt = ? WHERE id = ? AND sender_id = ?`,
      [encrypted_content, iv, salt, messageId, userId],
      function(err) {
        if (err) { console.error(err); return; }
        io.to(roomId).emit('message-edited', { messageId, encrypted_content, iv, salt });
      }
    );
  });

  socket.on('delete-message', ({ messageId, roomId }) => {
    db.run('UPDATE messages SET is_deleted = 1 WHERE id = ? AND sender_id = ?', [messageId, userId]);
    socket.to(roomId).emit('message-deleted', { messageId });
  });

  socket.on('disconnect', () => {
    console.log(`❌ ${socket.data.username} disconnected`);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
