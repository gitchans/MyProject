// index.js (JWT 인증 버전 + 통일 응답 포맷)

require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// ===== 환경변수 =====
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// ===== 공통 응답 포맷 미들웨어 =====
app.use((req, res, next) => {
  res.ok = (data = {}, code = 200) => res.status(code).json({ code, success: true, data });
  res.fail = (code = 400, message = 'Bad Request', detail) => {
    const payload = { code, success: false, error: { message } };
    if (detail !== undefined) payload.error.detail = detail;
    return res.status(code).json(payload);
  };
  next();
});

// ===== DB 연결 & 스키마 =====
const db = new Database('app.db');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  uid INTEGER PRIMARY KEY AUTOINCREMENT,
  login_id TEXT NOT NULL UNIQUE,   -- 회원가입/로그인용 아이디(이메일도 가능)
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  birth_date TEXT NOT NULL,        -- YYYY-MM-DD
  email TEXT,                      -- 선택, 필요 시 사용
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS medications (
  user_medication_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
  medication_name TEXT NOT NULL,
  dosage TEXT NOT NULL,
  frequency TEXT NOT NULL,
  start_date TEXT NOT NULL,        -- YYYY-MM-DD
  end_date TEXT,                   -- YYYY-MM-DD or null
  instructions TEXT,
  is_active INTEGER NOT NULL DEFAULT 1,  -- 1:true, 0:false
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS schedules (
  schedule_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_medication_id INTEGER NOT NULL REFERENCES medications(user_medication_id) ON DELETE CASCADE,
  time TEXT NOT NULL,             -- "HH:MM"
  days_of_week TEXT NOT NULL,     -- "Mon,Wed,Fri" 같은 CSV
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS logs (
  log_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_medication_id INTEGER NOT NULL REFERENCES medications(user_medication_id) ON DELETE CASCADE,
  scheduled_time TEXT NOT NULL,   -- ISO 문자열
  taken_time TEXT,                -- ISO or null
  status TEXT NOT NULL,           -- "taken" 등
  memo TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

// ===== 유틸 & 검증 =====
const isYMD = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s);
const isHM  = (s) => /^\d{2}:\d{2}$/.test(s);

// ===== JWT 유틸 =====
function signAccessToken(userId) {
  return jwt.sign({ user_id: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function authRequired(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.fail(401, 'UNAUTHORIZED');

  const token = m[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.user_id;
    next();
  } catch (err) {
    // TokenExpiredError, JsonWebTokenError 등
    const message = err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN';
    return res.fail(401, message);
  }
}

// =======================
// 1) 회원가입
// POST /api/users/register
// body: { name, birth_date, id, password }
// res:  { code, success, data: { user_id, message } }
// =======================
app.post('/api/users/register', (req, res) => {
  const { name, birth_date, id, password } = req.body || {};
  if (!name || !birth_date || !id || !password) {
    return res.fail(400, 'name, birth_date, id, password 모두 필요합니다.');
  }
  if (!isYMD(birth_date)) {
    return res.fail(400, 'birth_date는 YYYY-MM-DD 형식이어야 합니다.');
  }
  if (String(id).length < 3) {
    return res.fail(400, 'id는 최소 3자 이상이어야 합니다.');
  }
  if (String(password).length < 4) {
    return res.fail(400, 'password는 최소 4자 이상이어야 합니다.');
  }

  const dup = db.prepare('SELECT 1 FROM users WHERE login_id = ?').get(id);
  if (dup) return res.fail(409, '이미 존재하는 id 입니다.');

  const hash = bcrypt.hashSync(password, 10);
  db.prepare(`
    INSERT INTO users (login_id, password_hash, name, birth_date)
    VALUES (?, ?, ?, ?)
  `).run(id, hash, name, birth_date);

  return res.ok({ user_id: id, message: '회원가입 완료' }, 200);
});

// =======================
// 2) 로그인 (JWT 발급)
// POST /api/users/login
// body: { id, password }   (id는 login_id 또는 이메일로 간주)
// res:  { code, success, data: { token, user_id } }
// =======================
app.post('/api/users/login', (req, res) => {
  const { id, password } = req.body || {};
  if (!id || !password) return res.fail(400, 'id, password 필요');

  const user =
    db.prepare('SELECT * FROM users WHERE login_id = ?').get(id) ||
    db.prepare('SELECT * FROM users WHERE email = ?').get(id);

  if (!user) return res.fail(401, '잘못된 자격 증명');

  const ok = bcrypt.compareSync(String(password), user.password_hash);
  if (!ok) return res.fail(401, '잘못된 자격 증명');

  const token = signAccessToken(user.uid);
  return res.ok({ token, user_id: user.uid }, 200);
});

// =======================
// 3) 내 정보 조회 (인증 필요)
// GET /api/users/me
// header: Authorization: Bearer <token>
// res: { code, success, data: { user_id, name, email, birth_date } }
// =======================
app.get('/api/users/me', authRequired, (req, res) => {
  const u = db.prepare('SELECT uid, name, email, birth_date FROM users WHERE uid = ?').get(req.userId);
  if (!u) return res.fail(404, 'NOT_FOUND');
  return res.ok({
    user_id: u.uid,
    name: u.name,
    email: u.email || null,
    birth_date: u.birth_date
  }, 200);
});

// =======================
// 4) 복약 목록 조회
// GET /api/medications
// =======================
app.get('/api/medications', authRequired, (req, res) => {
  const rows = db.prepare(`
    SELECT user_medication_id, medication_name, dosage, frequency,
           start_date, end_date, instructions, (is_active=1) AS is_active
    FROM medications
    WHERE user_id = ?
    ORDER BY user_medication_id DESC
  `).all(req.userId);
  return res.ok(rows, 200);
});

// =======================
// 5) 복약 추가
// POST /api/medications
// body: { medication_name, dosage, frequency, start_date, end_date, instructions }
// res:  { code, success, data: { user_medication_id, message } }
// =======================
app.post('/api/medications', authRequired, (req, res) => {
  const { medication_name, dosage, frequency, start_date, end_date, instructions } = req.body || {};
  if (!medication_name || !dosage || !frequency || !start_date) {
    return res.fail(400, 'medication_name, dosage, frequency, start_date 필요');
  }
  if (!isYMD(start_date)) return res.fail(400, 'start_date 형식 오류(YYYY-MM-DD)');
  if (end_date && !isYMD(end_date)) return res.fail(400, 'end_date 형식 오류(YYYY-MM-DD)');

  const info = db.prepare(`
    INSERT INTO medications (user_id, medication_name, dosage, frequency, start_date, end_date, instructions)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(req.userId, medication_name, dosage, frequency, start_date, end_date || null, instructions || null);

  return res.ok({ user_medication_id: info.lastInsertRowid, message: '복약 등록 완료' }, 200);
});

// =======================
// 6) 복약 수정
// PUT /api/medications/:id
// body: 일부 필드만 보내도 됨 (부분수정 처리)
// =======================
app.put('/api/medications/:id', authRequired, (req, res) => {
  const id = Number(req.params.id);
  const med = db.prepare('SELECT * FROM medications WHERE user_medication_id = ? AND user_id = ?').get(id, req.userId);
  if (!med) return res.fail(404, 'NOT_FOUND');

  const { dosage, frequency, start_date, end_date, instructions, medication_name, is_active } = req.body || {};

  const patch = [];
  const vals = [];
  const set = (field, value) => { patch.push(`${field} = ?`); vals.push(value); };

  if (medication_name !== undefined) set('medication_name', medication_name);
  if (dosage !== undefined) set('dosage', dosage);
  if (frequency !== undefined) set('frequency', frequency);
  if (start_date !== undefined) {
    if (!isYMD(start_date)) return res.fail(400, 'start_date 형식 오류(YYYY-MM-DD)');
    set('start_date', start_date);
  }
  if (end_date !== undefined) {
    if (end_date && !isYMD(end_date)) return res.fail(400, 'end_date 형식 오류(YYYY-MM-DD)');
    set('end_date', end_date || null);
  }
  if (instructions !== undefined) set('instructions', instructions);
  if (is_active !== undefined) set('is_active', is_active ? 1 : 0);

  if (patch.length === 0) return res.ok({ message: '변경 없음' });

  set('updated_at', new Date().toISOString().replace('T',' ').replace('Z',''));
  vals.push(id);

  db.prepare(`UPDATE medications SET ${patch.join(', ')} WHERE user_medication_id = ?`).run(...vals);

  return res.ok({ message: '복약 정보 수정 완료' }, 200);
});

// =======================
// 7) 복약 삭제
// DELETE /api/medications/:id
// =======================
app.delete('/api/medications/:id', authRequired, (req, res) => {
  const id = Number(req.params.id);
  const info = db.prepare('DELETE FROM medications WHERE user_medication_id = ? AND user_id = ?').run(id, req.userId);
  if (info.changes === 0) return res.fail(404, 'NOT_FOUND');
  return res.ok({ message: '복약 삭제 완료' }, 200);
});

// =======================
// 8) 복약 스케줄 등록
// POST /api/schedules
// body: { user_medication_id, time("HH:MM"), days_of_week("Mon,Wed,Fri") }
// res:  { code, success, data: { schedule_id, message } }
// =======================
app.post('/api/schedules', authRequired, (req, res) => {
  const { user_medication_id, time, days_of_week } = req.body || {};
  if (!user_medication_id || !time || !days_of_week) {
    return res.fail(400, 'user_medication_id, time, days_of_week 필요');
  }
  if (!isHM(time)) return res.fail(400, 'time 형식 오류(HH:MM)');

  const med = db.prepare('SELECT 1 FROM medications WHERE user_medication_id = ? AND user_id = ?')
                .get(user_medication_id, req.userId);
  if (!med) return res.fail(404, '해당 복약이 없거나 권한 없음');

  const info = db.prepare(`
    INSERT INTO schedules (user_medication_id, time, days_of_week)
    VALUES (?, ?, ?)
  `).run(user_medication_id, time, days_of_week);

  return res.ok({ schedule_id: info.lastInsertRowid, message: '스케줄 등록 완료' }, 200);
});

// =======================
// 9) 스케줄 조회
// GET /api/schedules/:medicationId
// =======================
app.get('/api/schedules/:medicationId', authRequired, (req, res) => {
  const medicationId = Number(req.params.medicationId);
  const med = db.prepare('SELECT 1 FROM medications WHERE user_medication_id = ? AND user_id = ?')
                .get(medicationId, req.userId);
  if (!med) return res.fail(404, '해당 복약 없음/권한 없음');

  const rows = db.prepare(`
    SELECT schedule_id, time, days_of_week
    FROM schedules
    WHERE user_medication_id = ?
    ORDER BY schedule_id DESC
  `).all(medicationId);

  return res.ok(rows, 200);
});

// =======================
// 10) 복약 완료 체크(기록)
// POST /api/logs
// body: { user_medication_id, scheduled_time, taken_time, status, memo }
// res:  { code, success, data: { log_id, message } }
// =======================
app.post('/api/logs', authRequired, (req, res) => {
  const { user_medication_id, scheduled_time, taken_time, status, memo } = req.body || {};
  if (!user_medication_id || !scheduled_time || !status) {
    return res.fail(400, 'user_medication_id, scheduled_time, status 필요');
  }
  const med = db.prepare('SELECT 1 FROM medications WHERE user_medication_id = ? AND user_id = ?')
                .get(user_medication_id, req.userId);
  if (!med) return res.fail(404, '해당 복약이 없거나 권한 없음');

  const info = db.prepare(`
    INSERT INTO logs (user_medication_id, scheduled_time, taken_time, status, memo)
    VALUES (?, ?, ?, ?, ?)
  `).run(user_medication_id, scheduled_time, taken_time || null, status, memo || null);

  return res.ok({ log_id: info.lastInsertRowid, message: '복약 기록 완료' }, 200);
});

// =======================
// 11) 복약 기록 조회
// GET /api/logs/:medicationId
// =======================
app.get('/api/logs/:medicationId', authRequired, (req, res) => {
  const medicationId = Number(req.params.medicationId);
  const med = db.prepare('SELECT 1 FROM medications WHERE user_medication_id = ? AND user_id = ?')
                .get(medicationId, req.userId);
  if (!med) return res.fail(404, '해당 복약이 없거나 권한 없음');

  const rows = db.prepare(`
    SELECT scheduled_time, taken_time, status, memo
    FROM logs
    WHERE user_medication_id = ?
    ORDER BY log_id DESC
  `).all(medicationId);

  return res.ok(rows, 200);
});

// ===== 404 핸들러 =====
app.use((req, res) => {
  return res.fail(404, 'Endpoint Not Found');
});

// ===== 에러 핸들러(최종) =====
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  return res.fail(500, 'Internal Server Error');
});

// 서버 시작
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`API 서버 실행: http://localhost:${PORT}`));
