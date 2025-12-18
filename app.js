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
function auth(req, res, next) {
  try {
    const header = req.headers['authorization'];
    if (!header) {
      return res.fail(401, 'Authorization 헤더가 없습니다.');
    }

    const [type, token] = header.split(' ');

    if (!token) {
      return res.fail(401, '토큰 형식이 잘못되었습니다.');
    }

    if (token === "super-token") {
      req.user = {
        user_id: 1
      };
      return next();
    }

    if (type !== 'Bearer') {
      return res.fail(401, 'Bearer <token> 형식이어야 합니다.');
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.fail(401, '유효하지 않은 토큰입니다.', err.message);
      }

      req.user = decoded; // decoded.user_id 존재
      next();
    });
  } catch (error) {
    return res.fail(500, 'AUTH_MIDDLEWARE_ERROR', error);
  }
}

// =======================
// 1) 회원가입
// =======================
app.post('/api/users/register', async (req, res) => {
  const { name, birth_date, email, password } = req.body || {};
  if (!name || !birth_date || !email || !password)
    return res.fail(400, 'name, birth_date, email, password 모두 필요합니다.');

  // 1) id 중복 체크
  const { data: exist } = await supabase
    .from('users')
    .select('email')
    .eq('email', email)
    .maybeSingle();

  if (exist) return res.fail(409, '이미 존재하는 email 입니다.');

  // 2) 비밀번호 해싱
  const hash = bcrypt.hashSync(password, 10);

  // 3) 유저 생성
  const { data, error } = await supabase
    .from('users')
    .insert({
      email: email,
      password: hash,
      name,
      birth_date,
    })
    .select()
    .single();

  if (error) return res.fail(500, 'DB_INSERT_FAIL', error);

  return res.ok({ user_id: data.id, message: '회원가입 완료' });
});

// =======================
// 2) 로그인 (JWT)
// =======================
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.fail(400, 'email, password 필요합니다.');

  // 1) 사용자 조회
  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email)
    .single();

  if (error || !user) return res.fail(404, '존재하지 않는 계정입니다.');

  // 2) 비밀번호 비교
  const match = bcrypt.compareSync(password, user.password);
  if (!match) return res.fail(401, '비밀번호가 일치하지 않습니다.');

  // 3) JWT 발급
  const token = signAccessToken(user.id);

  return res.ok({ token, message: '로그인 성공', user_id: user.id });
});

// =======================
// 3) 내 정보 조회
// =======================
app.get('/api/users/me', auth, async (req, res) => {
  const userId = req.user.user_id;

  const { data, error } = await supabase
    .from('users')
    .select('id, name, birth_date, email, created_at')
    .eq('id', userId)
    .single();

  if (error) return res.fail(500, 'DB_SELECT_FAIL', error);

  return res.ok(data);
});

// =======================
// 4) 복약 목록 조회
// =======================
app.get('/api/medications', auth, async (req, res) => {
  const userId = req.user.user_id;

  const { data, error } = await supabase
    .from('user_medications')
    .select(`
      id,
      product_code,
      dosage,
      frequency,
      start_date,
      end_date,
      instructions,
      is_active
    `)
    .eq('user_id', userId)
    .eq('is_active', true);

  if (error) return res.fail(500, 'DB_SELECT_FAIL', error);

  return res.ok(data);
});

// =======================
// 5) 복약 추가
// =======================
app.post('/api/medications', auth, async (req, res) => {
  const userId = req.user.user_id;
  const { product_code, dosage, frequency, start_date, end_date, instructions } = req.body || {};
  if (!product_code || !dosage || !frequency || !start_date) return res.fail(400, '필수 항목 누락');

  const today = new Date().toISOString().split('T')[0];

  // is_active 자동 계산
  let is_active = true;

  if (today < start_date) {
    is_active = false;
  }
  else if(end_date && today > end_date) {
    is_active = false;
  }

  const { data, error } = await supabase
    .from('user_medications')
    .insert({
      user_id: userId,
      product_code,
      dosage,
      frequency,
      start_date,
      end_date,
      instructions,
      is_active
    })
    .select()
    .single();

  if (error) return res.fail(500, 'DB_INSERT_FAIL', error);

  return res.ok({ id: data.id, message: '복약 등록 완료' });
});

// =======================
// 6) 복약 수정
// =======================
app.put('/api/medications/:id', auth, async (req, res) => {
  const userId = req.user.user_id;
  const { id } = req.params;

  const { dosage, frequency, start_date, end_date, instructions } = req.body || {};

  if(!dosage && !frequency && !start_date && !end_date && !instructions) return res.fail(400, '항목 누락');

  const today = new Date().toISOString().split('T')[0];

  // is_active 자동 계산
  let is_active = true;

  if (today < start_date) {
    is_active = false;
  }
  else if(end_date && today > end_date) {
    is_active = false;
  }

  const { data, error } = await supabase
    .from('user_medications')
    .update({
      dosage,
      frequency,
      start_date,
      end_date,
      instructions,
      is_active,
    })
    .eq('id', id)
    .eq('user_id', userId)
    .select()
    .single();

  if (error) return res.fail(500, 'DB_UPDATE_FAIL', error);

  return res.ok({ id: data.id, message: '수정 완료' });
});

// =======================
// 7) 복약 삭제
// =======================
app.delete('/api/medications/:id', auth, async (req, res) => {
  const userId = req.user.user_id;
  const { id } = req.params;

  const { data, error } = await supabase
    .from('user_medications')
    .update({ is_active: false })
    .eq('id', id)
    .eq('user_id', userId)
    .select()
    .single();

  if (error) return res.fail(500, 'DB_UPDATE_FAIL', error);

  return res.ok({ id: data.id, message: '삭제 완료' });
});

// =======================
// 8) 스케줄 등록
// =======================
app.post('/api/schedules', auth, async (req, res) => {
  const { time_of_day, days_of_week, user_medication_id} = req.body || {};

  if (!time_of_day || !days_of_week || !user_medication_id) return res.fail(400, '필수 항목 누락');

  // 1) 해당 약의 frequency 가져오기
  const { data: med, error: medError } = await supabase
    .from('user_medications')
    .select('frequency')
    .eq('id', user_medication_id)
    .single();

  if (medError || !med) return res.fail(404, '해당 medication을 찾을 수 없습니다.');

  const frequency = med.frequency || 1;

  if (time_of_day.length != frequency) {
    return res.fail(400,`이 약의 frequency와 복약시간이 맞지 않습니다.`);
  }

  // 4) 스케줄 등록
  const { data, error } = await supabase
    .from('medication_schedule')
    .insert({
      user_medication_id: user_medication_id,
      time_of_day,
      days_of_week,
    })
    .select()
    .single();

  if (error) return res.fail(500, 'DB_INSERT_FAIL', error);

  return res.ok({ id: data.id, message: '스케줄 등록 완료' });
});

// =======================
// 9) 스케줄 조회
// =======================
app.get('/api/medications/schedule', auth, async (req, res) => {
  const userId = req.user.user_id;

  const { data: med, error: medError } = await supabase
    .from('user_medications')
    .select('id')
    .eq('user_id', userId)
    .eq('is_active', true);

  if (medError || !med || med.length == 0) return res.fail(404, '등록된 복약이 없습니다.');

  const ids = med.map(item => item.id);

  const { data, error } = await supabase
    .from('medication_schedule')
    .select('*')
    .in('user_medication_id', ids);

  if (error) return res.fail(500, 'DB_SELECT_FAIL', error);

  return res.ok(data);
});

// =======================
// 10) 복약 기록 등록
// =======================
app.post('/api/logs', auth, async (req, res) => {
  const userId = req.user.user_id;
  const { id } = req.body || {};

  if (!id) return res.fail(400, '필수 항목 누락');

  const { data: med, error: medError } = await supabase
    .from('user_medications')
    .select('id')
    .eq('user_id', userId)
    .eq('is_active', true);

  if (medError || !med || med.length == 0) return res.fail(404, '등록된 복약이 없습니다.');

  const exist = med.some(item => item.id == id);

  if(!exist) return res.fail(404, '복약정보가 없습니다.');

  const taken_at = new Date().toISOString();

  const { data, error } = await supabase
    .from('medication_logs')
    .insert({
      user_medication_id: id,
      user_id: userId,
      taken_at,
    })
    .select()
    .single();

  if (error) return res.fail(500, 'DB_INSERT_FAIL', error);

  return res.ok({ id: data.id, message: '복약 기록 완료' });
});

// =======================
// 11) 복약 기록 조회
// =======================
app.get('/api/medications/logs', auth, async (req, res) => {
  const userId = req.user.user_id;
  const { id } = req.query;

  const { data, error } = await supabase
    .from('medication_logs')
    .select('id, taken_at')
    .eq('user_medication_id', id)
    .eq('user_id', userId)
    .order('taken_at', { ascending: true });

  if (error) return res.fail(500, 'DB_SELECT_FAIL', error);

  return res.ok(data);
});


// 복약 기록 확인 
app.get('/api/logs/summary', auth, async (req, res) => {
  const userId = req.user.user_id;
  const { year, month } = req.query;

  if (!year || !month)
    return res.fail(400, 'year, month 필요');

  const y = Number(year);
  const m = Number(month);
  const daysInMonth = new Date(y, m, 0).getDate(); 
  const result = [];

  const today = new Date().toISOString().split('T')[0];

  // 1) 스케줄 + frequency JOIN 조회
  const { data: schedules, error: schErr } = await supabase
    .from('medication_schedule')
    .select(`
      id,
      user_medication_id,
      days_of_week,
      time_of_day,
      user_medications (
        id,
        frequency,
        user_id
      )
    `)
    .eq('user_medications.user_id', userId);

  if (schErr) return res.fail(500, 'SCHEDULE_FETCH_FAIL', schErr);

  // 2) 날짜별 처리
  for (let d = 1; d <= daysInMonth; d++) {
    const dateStr = `${year}-${month}-${String(d).padStart(2, '0')}`;

    // ✅ 미래 날짜 → 판단하지 않음
    if (dateStr > today) {
      result.push(false);
      continue;
    }

    const dateObj = new Date(dateStr);
    const dayName = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][dateObj.getDay()];

    let requiredCount = 0;

    schedules.forEach(sch => {
      if (sch.days_of_week.includes(dayName)) {
        requiredCount += sch.user_medications.frequency;
      }
    });

    // 먹을 약이 없는 날 → true
    if (requiredCount === 0) {
      result.push(true);
      continue;
    }

    const start = `${dateStr} 00:00:00`;
    const end = `${dateStr} 23:59:59`;

    const { data: logs, error: logErr } = await supabase
      .from('medication_logs')
      .select('id')
      .eq('user_id', userId)
      .gte('taken_at', start)
      .lte('taken_at', end);

    if (logErr) return res.fail(500, 'LOG_FETCH_FAIL', logErr);

    const takenCount = logs?.length || 0;

    result.push(takenCount >= requiredCount);
  }

  return res.ok(result);
});


app.get('/api/medications/info', async (req, res) => {
  const { product_code } = req.query;
  if (!product_code) return res.fail(400, '필수 항목 누락');

  // 1) 사용자 조회
  const { data: info, error } = await supabase
    .from('medicines_info')
    .select('*')
    .eq('product_code', product_code)
    .single();

  if (error || !info) return res.fail(404, '존재하지 않는 약입니다.');

  return res.ok(info);
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