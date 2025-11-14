import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';

const projectUrl = 'https://ypuscqrqarrfvahdpycy.supabase.co';
const key = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlwdXNjcXJxYXJyZnZhaGRweWN5Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjI5MzA1ODMsImV4cCI6MjA3ODUwNjU4M30.t4k6Bo5mw3wnyrNWiqMGh5YSxMHgDuGxk4FqxiY4370';

const app = express();
app.use(express.json());

// ===== Supabase 초기화 =====
const supabase = createClient(projectUrl, key);

// ===== JWT =====
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';

// ===== 공통 응답 포맷 =====
app.use((req, res, next) => {
  res.ok = (data = {}, code = 200) => res.status(code).json({ code, success: true, data });
  res.fail = (code = 400, message = 'Bad Request', detail) => {
    const payload = { code, success: false, error: { message } };
    if (detail !== undefined) payload.error.detail = detail;
    return res.status(code).json(payload);
  };
  next();
});

// ===== 유틸 =====
const isYMD = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s);
const isHM = (s) => /^\d{2}:\d{2}$/.test(s);

// ===== JWT 유틸 =====
function signAccessToken(userId) {
  return jwt.sign({ user_id: userId }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// 인증 미들웨어
function authRequired(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.fail(401, 'UNAUTHORIZED');

  try {
    const decoded = jwt.verify(m[1], JWT_SECRET);
    req.userId = decoded.user_id;
    next();
  } catch (err) {
    const message = err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN';
    return res.fail(401, message);
  }
}

app.post('/api/users/register', async (req, res) => {
  const { name, birth_date, id, password } = req.body || {};
  if (!name || !birth_date || !id || !password)
    return res.fail(400, 'name, birth_date, id, password 모두 필요합니다.');

  // 중복 확인
  const { data: exist } = await supabase
    .from('users')
    .select('uid')
    .eq('login_id', id)
    .maybeSingle();

  if (exist) return res.fail(409, '이미 존재하는 id 입니다.');

  const hash = bcrypt.hashSync(password, 10);

  const { data, error } = await supabase
    .from('users')
    .insert({
      login_id: id,
      password_hash: hash,
      name,
      birth_date,
    })
    .select()
    .single();

  if (error) return res.fail(500, 'DB_INSERT_FAIL', error);

  return res.ok({ user_id: data.uid, message: '회원가입 완료' });
});

// =======================
// 2) 로그인 (JWT)
// =======================
app.post('/api/users/login', async (req, res) => {
  const { id, password } = req.body || {};
  if (!id || !password) return res.fail(400, 'id, password 필요');

  // login_id 또는 email 로 검색
  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .or(`login_id.eq.${id},email.eq.${id}`)
    .maybeSingle();

  if (!user) return res.fail(401, '잘못된 자격 증명');

  const ok = bcrypt.compareSync(String(password), user.password_hash);
  if (!ok) return res.fail(401, '잘못된 자격 증명');

  const token = signAccessToken(user.uid);
  return res.ok({ token, user_id: user.uid });
});

// =======================
// 3) 내 정보 조회
// =======================
app.get('/api/users/me', authRequired, async (req, res) => {
  const { data: u, error } = await supabase
    .from('users')
    .select('uid, name, email, birth_date')
    .eq('uid', req.userId)
    .maybeSingle();

  if (!u) return res.fail(404, 'NOT_FOUND');
  return res.ok({
    user_id: u.uid,
    name: u.name,
    email: u.email,
    birth_date: u.birth_date,
  });
});

// =======================
// 4) 복약 목록 조회
// =======================
app.get('/api/medications', authRequired, async (req, res) => {
  const { data, error } = await supabase
    .from('medications')
    .select('user_medication_id, medication_name, dosage, frequency, start_date, end_date, instructions, is_active')
    .eq('user_id', req.userId)
    .order('user_medication_id', { ascending: false });

  return res.ok(data);
});

// =======================
// 5) 복약 추가
// =======================
app.post('/api/medications', authRequired, async (req, res) => {
  const { medication_name, dosage, frequency, start_date, end_date, instructions } = req.body || {};
  if (!medication_name || !dosage || !frequency || !start_date)
    return res.fail(400, '필수 항목 누락');

  const { data, error } = await supabase
    .from('medications')
    .insert({
      user_id: req.userId,
      medication_name,
      dosage,
      frequency,
      start_date,
      end_date: end_date || null,
      instructions: instructions || null,
    })
    .select()
    .single();

  if (error) return res.fail(500, 'DB_INSERT_FAIL', error);

  return res.ok(
    { user_medication_id: data.user_medication_id, message: '복약 등록 완료' },
    200
  );
});

// =======================
// 6) 복약 수정
// =======================
app.put('/api/medications/:id', authRequired, async (req, res) => {
  const id = Number(req.params.id);

  const { data: med } = await supabase
    .from('medications')
    .select('*')
    .eq('user_medication_id', id)
    .eq('user_id', req.userId)
    .maybeSingle();

  if (!med) return res.fail(404, 'NOT_FOUND');

  const patch = req.body;

  patch.updated_at = new Date().toISOString();

  const { error } = await supabase
    .from('medications')
    .update(patch)
    .eq('user_medication_id', id);

  if (error) return res.fail(500, 'DB_UPDATE_FAIL', error);

  return res.ok({ message: '복약 정보 수정 완료' });
});

// =======================
// 7) 복약 삭제
// =======================
app.delete('/api/medications/:id', authRequired, async (req, res) => {
  const id = Number(req.params.id);

  const { error, count } = await supabase
    .from('medications')
    .delete()
    .eq('user_medication_id', id)
    .eq('user_id', req.userId);

  return res.ok({ message: '복약 삭제 완료' });
});

// =======================
// 8) 스케줄 등록
// =======================
app.post('/api/schedules', authRequired, async (req, res) => {
  const { user_medication_id, time, days_of_week } = req.body || {};

  const { data: med } = await supabase
    .from('medications')
    .select('user_medication_id')
    .eq('user_medication_id', user_medication_id)
    .eq('user_id', req.userId)
    .maybeSingle();

  if (!med) return res.fail(404, '해당 복약 없음');

  const { data, error } = await supabase
    .from('schedules')
    .insert({ user_medication_id, time, days_of_week })
    .select()
    .single();

  return res.ok({ schedule_id: data.schedule_id, message: '스케줄 등록 완료' });
});

// =======================
// 9) 스케줄 조회
// =======================
app.get('/api/schedules/:medicationId', authRequired, async (req, res) => {
  const medicationId = Number(req.params.medicationId);

  const { data, error } = await supabase
    .from('schedules')
    .select()
    .eq('user_medication_id', medicationId)
    .order('schedule_id', { ascending: false });

  return res.ok(data);
});

// =======================
// 10) 복약 기록 등록
// =======================
app.post('/api/logs', authRequired, async (req, res) => {
  const { user_medication_id, scheduled_time, taken_time, status, memo } = req.body || {};

  const { data: med } = await supabase
    .from('medications')
    .select('user_medication_id')
    .eq('user_medication_id', user_medication_id)
    .eq('user_id', req.userId)
    .maybeSingle();

  if (!med) return res.fail(404, '해당 복약 없음');

  const { data, error } = await supabase
    .from('logs')
    .insert({
      user_medication_id,
      scheduled_time,
      taken_time: taken_time || null,
      status,
      memo: memo || null,
    })
    .select()
    .single();

  return res.ok({ log_id: data.log_id, message: '복약 기록 완료' });
});

// =======================
// 11) 복약 기록 조회
// =======================
app.get('/api/logs/:medicationId', authRequired, async (req, res) => {
  const medicationId = Number(req.params.medicationId);

  const { data } = await supabase
    .from('logs')
    .select()
    .eq('user_medication_id', medicationId)
    .order('log_id', { ascending: false });

  return res.ok(data);
});


// 복약 기록 확인 
app.get('/api/medications/check/monthly', authRequired, async (req, res) => {
  const { month } = req.query;
  const userId = req.userId;

  if (!month || !/^\d{4}-\d{2}$/.test(month)) {
    return res.fail(400, 'month는 YYYY-MM 형식이어야 합니다.');
  }

  // 날짜 범위 계산
  const [year, mm] = month.split('-').map(Number);
  const firstDay = new Date(year, mm - 1, 1);
  const lastDay = new Date(year, mm, 0); // 해당 달의 마지막 날
  const totalDays = lastDay.getDate();

  // 1. 해당 유저의 모든 medications 조회
  const { data: meds, error: medErr } = await supabase
    .from('medications')
    .select('user_medication_id, is_active')
    .eq('user_id', userId);

  if (medErr) return res.fail(500, 'DB_ERROR', medErr);

  const medicationIds = meds.map((m) => m.user_medication_id);
  if (medicationIds.length === 0)
    return res.ok({
      user_id: userId,
      month,
      daily_check: Array(totalDays).fill(true) // 복약할 약이 없으면 모두 true 처리
    });

  // 2. 이 약들의 스케줄 전체 조회
  const { data: schedules, error: schErr } = await supabase
    .from('schedules')
    .select('schedule_id, user_medication_id, time, days_of_week')
    .in('user_medication_id', medicationIds);

  if (schErr) return res.fail(500, 'DB_ERROR', schErr);

  // 3. 이 달의 모든 로그 조회
  const { data: logs, error: logErr } = await supabase
    .from('logs')
    .select('user_medication_id, scheduled_time, status')
    .in('user_medication_id', medicationIds)
    .gte('scheduled_time', firstDay.toISOString())
    .lte('scheduled_time', new Date(year, mm, 1).toISOString());

  if (logErr) return res.fail(500, 'DB_ERROR', logErr);

  // 4. 날짜별 체크
  const daily_check = [];

  for (let day = 1; day <= totalDays; day++) {
    const current = new Date(year, mm - 1, day);

    const weekday = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][ current.getDay() ];

    // 오늘 복용해야 하는 스케줄 개수
    const todaysSchedules = schedules.filter((s) =>
      s.days_of_week.split(',').map(x=>x.trim()).includes(weekday)
    );

    const scheduleCount = todaysSchedules.length;

    if (scheduleCount === 0) {
      // 복약할 게 없다면 true
      daily_check.push(true);
      continue;
    }

    // 오늘 복용 기록 조회
    const dayStr = current.toISOString().split('T')[0]; // YYYY-MM-DD

    const todaysLogs = logs.filter((log) =>
      log.scheduled_time.startsWith(dayStr) &&
      (log.status === 'taken')
    );

    const takenCount = todaysLogs.length;

    daily_check.push(takenCount >= scheduleCount);
  }

  return res.ok({
    user_id: userId,
    month,
    daily_check
  });
});

// =======================
// 404
// =======================
app.use((req, res) => res.fail(404, 'Endpoint Not Found'));

// =======================
// 전역 에러
// =======================
app.use((err, req, res, next) => {
  console.error(err);
  return res.fail(500, 'Internal Server Error');
});


// =======================================
// 서버 시작
// =======================================
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`API 서버 실행: http://localhost:${PORT}`));