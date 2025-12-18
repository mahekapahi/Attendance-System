from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, session, flash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3, os, time, hmac, hashlib, io, csv
from collections import defaultdict
from datetime import datetime
import qrcode

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = os.getenv('FLASK_SECRET', 'dev-change-this-secret')

DB_PATH = os.path.join('data', 'attendance.db')
os.makedirs('data', exist_ok=True)

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  full_name TEXT NOT NULL,
  roll_no TEXT,
  role TEXT NOT NULL CHECK(role IN ('teacher','student')),
  password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  course TEXT NOT NULL,
  room TEXT,
  start_ts INTEGER NOT NULL,
  end_ts   INTEGER NOT NULL,
  secret   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL,
  roll_no TEXT NOT NULL,
  name TEXT NOT NULL,
  marked_ts INTEGER NOT NULL,
  device TEXT,
  UNIQUE(session_id, roll_no)
);
'''

def db():
  con = sqlite3.connect(DB_PATH)
  con.row_factory = sqlite3.Row
  return con

def init_db():
  with db() as con:
    con.executescript(SCHEMA)
init_db()

def seed_users():
  with db() as con:
    for i in range(1, 11):
      try:
        con.execute('INSERT INTO users(username, full_name, roll_no, role, password_hash) VALUES (?,?,?,?,?)',
                    (f"t{i}", f"Teacher {i}", None, 'teacher', generate_password_hash('teach123')))
      except sqlite3.IntegrityError:
        pass
    for n in range(62, 113):
      try:
        con.execute('INSERT INTO users(username, full_name, roll_no, role, password_hash) VALUES (?,?,?,?,?)',
                    (f"c{n}", f"Student {n}", f"C{n}", 'student', generate_password_hash('stud123')))
      except sqlite3.IntegrityError:
        pass
seed_users()

def login_required(f):
  @wraps(f)
  def wrapper(*args, **kwargs):
    if 'user_id' not in session:
      return redirect(url_for('login', next=request.path))
    return f(*args, **kwargs)
  return wrapper

def role_required(role):
  def deco(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
      if 'user_id' not in session or session.get('role') != role:
        return redirect(url_for('login', next=request.path))
      return f(*args, **kwargs)
    return wrapper
  return deco

WINDOW = 30

def _counter(now=None):
  if now is None:
    now = int(time.time())
  return now // WINDOW

def sign(secret: str, counter: int) -> str:
  mac = hmac.new(secret.encode(), str(counter).encode(), hashlib.sha256).digest()
  return mac.hex()

def verify(secret: str, token: str) -> bool:
  now = _counter()
  for c in (now-1, now, now+1):
    if hmac.compare_digest(sign(secret, c), token):
      return True
  return False

def join_sig(secret: str) -> str:
  return hmac.new(secret.encode(), b"join", hashlib.sha256).hexdigest()

def _slot_from_hour(hr:int) -> str:
  if 6 <= hr < 12: return "Morning (06–12)"
  if 12 <= hr < 17: return "Afternoon (12–17)"
  if 17 <= hr < 22: return "Evening (17–22)"
  return "Off-hours"

def _iso_week_key(ts: int):
  d = datetime.fromtimestamp(ts)
  iso = d.isocalendar()
  return (iso.year, iso.week)

def compute_student_stats(roll_no: str):
  with db() as con:
    total_sessions = con.execute('SELECT COUNT(*) AS c FROM sessions').fetchone()['c']
    rows = con.execute('''
      SELECT a.session_id, a.marked_ts, a.device,
             s.course, s.room, s.start_ts, s.end_ts
      FROM attendance a
      JOIN sessions s ON s.id = a.session_id
      WHERE a.roll_no=?
      ORDER BY a.marked_ts DESC
    ''', (roll_no,)).fetchall()
  attended_sessions = len(rows)
  attendance_pct = round(100.0 * attended_sessions / total_sessions, 1) if total_sessions else 0
  days = []
  seen_dates = set()
  for r in rows:
    d = datetime.fromtimestamp(r['marked_ts']).date()
    if d not in seen_dates:
      seen_dates.add(d); days.append(d)
  days.sort(reverse=True)
  current_streak = 0
  if days:
    cur = days[0]; current_streak = 1
    for nxt in days[1:]:
      if (cur - nxt).days == 1:
        current_streak += 1; cur = nxt
      else:
        break
  best_streak = 0
  if days:
    run = 1
    for i in range(1, len(days)):
      if (days[i-1] - days[i]).days == 1:
        run += 1
      else:
        best_streak = max(best_streak, run); run = 1
    best_streak = max(best_streak, run)
  ontime_marks = 0
  for r in rows:
    if r['start_ts'] and (r['marked_ts'] - r['start_ts']) <= 10*60:
      ontime_marks += 1
  ontime_ratio = round(100.0 * ontime_marks / attended_sessions, 1) if attended_sessions else 0
  badges = []
  if ontime_ratio >= 80: badges.append("On-time (≥80% within first 10 min)")
  week_days = defaultdict(set)
  for r in rows:
    wk = _iso_week_key(r['marked_ts'])
    week_days[wk].add(datetime.fromtimestamp(r['marked_ts']).date())
  if any(len(s) >= 5 for s in week_days.values()):
    badges.append("Perfect Week (5+ attended days in a week)")
  if best_streak >= 3:
    badges.append(f"Streaker ({best_streak} days)")
  slot_counts = defaultdict(int)
  for r in rows:
    hr = datetime.fromtimestamp(r['start_ts']).hour
    slot_counts[_slot_from_hour(hr)] += 1
  top_slots = sorted(slot_counts.items(), key=lambda kv: kv[1], reverse=True)[:3]
  last_devices = [(r['device'] or '') for r in rows[:5]]
  return {
    "total_sessions": total_sessions,
    "attended_sessions": attended_sessions,
    "attendance_pct": attendance_pct,
    "current_streak_days": current_streak,
    "best_streak_days": best_streak,
    "ontime_ratio": ontime_ratio,
    "badges": badges,
    "top_slots": top_slots,
    "last_devices": last_devices,
    "rows": rows,
  }

@app.get('/login')
def login():
  if 'user_id' in session:
    return redirect(url_for('dashboard' if session.get('role')=='teacher' else 'me'))
  nxt = request.args.get('next', '')
  return render_template('login.html', nxt=nxt)

@app.post('/login')
def do_login():
  username = (request.form.get('username') or '').strip()
  password = request.form.get('password') or ''
  with db() as con:
    user = con.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
  if not user or not check_password_hash(user['password_hash'], password):
    flash('Invalid username or password', 'error')
    return redirect(url_for('login'))
  session['user_id'] = user['id']
  session['username'] = user['username']
  session['full_name'] = user['full_name']
  session['roll_no'] = user['roll_no']
  session['role'] = user['role']
  nxt = request.args.get('next')
  if nxt:
    return redirect(nxt)
  return redirect(url_for('dashboard' if user['role']=='teacher' else 'me'))

@app.post('/logout')
def logout():
  session.clear()
  return redirect(url_for('login'))

@app.route('/')
def home():
  if 'user_id' in session:
    return redirect(url_for('dashboard' if session.get('role')=='teacher' else 'me'))
  return redirect(url_for('login'))

@app.post('/start')
@role_required('teacher')
def start_session():
  course = request.form.get('course', 'CS101')
  room = request.form.get('room', '')
  dur_min = int(request.form.get('duration', '60'))
  online = request.form.get('online') == '1'
  if online:
    room = 'ONLINE'
  start_ts = int(time.time())
  end_ts = start_ts + dur_min*60
  secret = hashlib.sha256(os.urandom(32)).hexdigest()
  with db() as con:
    cur = con.execute('INSERT INTO sessions(course, room, start_ts, end_ts, secret) VALUES(?,?,?,?,?)',
                      (course, room, start_ts, end_ts, secret))
    sid = cur.lastrowid
  return redirect(url_for('session_view', session_id=sid))

@app.post('/end_session/<int:session_id>')
@role_required('teacher')
def end_session(session_id):
  with db() as con:
    s = con.execute('SELECT * FROM sessions WHERE id=?', (session_id,)).fetchone()
    if not s:
      return 'Session not found', 404
    now = int(time.time())
    con.execute('UPDATE sessions SET end_ts=? WHERE id=?', (now, session_id))
  return redirect(url_for('dashboard'))

@app.get('/session/<int:session_id>')
def session_view(session_id):
  with db() as con:
    s = con.execute('SELECT * FROM sessions WHERE id=?', (session_id,)).fetchone()
    if not s:
      return 'Session not found', 404
    count = con.execute('SELECT COUNT(*) AS c FROM attendance WHERE session_id=?', (session_id,)).fetchone()['c']
  join_url = None
  if s['room'] == 'ONLINE':
    base = request.host_url.rstrip('/')
    sig = join_sig(s['secret'])
    join_url = f"{base}{url_for('join_session', session_id=session_id)}?sig={sig}"
  return render_template('session.html', s=s, count=count, window=WINDOW, join_url=join_url)

@app.get('/qr/<int:session_id>.png')
def qr_png(session_id):
  with db() as con:
    s = con.execute('SELECT * FROM sessions WHERE id=?', (session_id,)).fetchone()
    if not s:
      return 'No session', 404
  tok = sign(s['secret'], _counter())
  base = request.host_url.rstrip('/')
  host = base.replace('http://', '').replace('https://', '')
  if host.startswith('localhost') or host.startswith('127.0.0.1'):
    ip = os.getenv('HOST_IP')
    if ip:
      port = host.split(':')[1] if ':' in host else '5001'
      base = f'http://{ip}:{port}'
  mark_url = base + url_for('scan', session_id=session_id, token=tok)
  img = qrcode.make(mark_url)
  buf = io.BytesIO()
  img.save(buf, format='PNG')
  buf.seek(0)
  resp = send_file(buf, mimetype='image/png')
  resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
  return resp

@app.get('/join/<int:session_id>')
def join_session(session_id):
  sig = request.args.get('sig', '')
  with db() as con:
    s = con.execute('SELECT * FROM sessions WHERE id=?', (session_id,)).fetchone()
  if not s or s['room'] != 'ONLINE':
    return 'Invalid online session', 400
  now = int(time.time())
  if now < s['start_ts'] or now > s['end_ts']:
    return 'Session closed or not started', 400
  if not hmac.compare_digest(join_sig(s['secret']), sig):
    return 'Join link invalid', 400
  return render_template('scan.html', s=s, token='', link_sig=sig)

@app.get('/scan')
def scan():
  session_id = int(request.args.get('session_id', '0'))
  token = request.args.get('token', '')
  with db() as con:
    s = con.execute('SELECT * FROM sessions WHERE id=?', (session_id,)).fetchone()
  if not s:
    return 'Invalid session', 400
  now = int(time.time())
  if now < s['start_ts'] or now > s['end_ts']:
    return 'Session closed or not started', 400
  if s['room'] != 'ONLINE' and not verify(s['secret'], token):
    return 'QR expired – ask teacher to rotate (it auto-rotates)', 400
  return render_template('scan.html', s=s, token=token)

@app.post('/mark')
def mark():
  session_id = int(request.form['session_id'])
  token = request.form.get('token', '')
  link_sig = request.form.get('link_sig', '')
  device = request.headers.get('User-Agent', '')[:120]
  roll_no = (request.form.get('roll_no') or '').strip().upper()
  password = request.form.get('password') or ''
  with db() as con:
    s = con.execute('SELECT * FROM sessions WHERE id=?', (session_id,)).fetchone()
  if not s:
    return 'Invalid session', 400
  now = int(time.time())
  if now < s['start_ts'] or now > s['end_ts']:
    return 'Session closed or not started', 400
  ok = False
  if s['room'] == 'ONLINE':
    ok = hmac.compare_digest(join_sig(s['secret']), link_sig)
  else:
    ok = verify(s['secret'], token)
  if not ok:
    return 'Invalid or expired token', 400
  with db() as con:
    user = con.execute('SELECT * FROM users WHERE role="student" AND roll_no=?', (roll_no,)).fetchone()
  if not user or not check_password_hash(user['password_hash'], password):
    return 'Invalid roll number or password', 401
  name = user['full_name']
  try:
    with db() as con:
      con.execute('INSERT INTO attendance(session_id, roll_no, name, marked_ts, device) VALUES(?,?,?,?,?)',
                  (session_id, roll_no, name, int(time.time()), device))
    return redirect(url_for('scan_success', session_id=session_id))
  except sqlite3.IntegrityError:
    return 'Already marked for this session', 200

@app.get('/scan/success')
def scan_success():
  session_id = int(request.args.get('session_id'))
  return f"Marked present ✅ (Session {session_id}). You may close this page."

@app.get('/live_count/<int:session_id>')
def live_count(session_id):
  with db() as con:
    c = con.execute('SELECT COUNT(*) AS c FROM attendance WHERE session_id=?', (session_id,)).fetchone()['c']
  return jsonify({ 'count': c })

@app.get('/export/<int:session_id>')
@role_required('teacher')
def export(session_id):
  with db() as con:
    s = con.execute('SELECT * FROM sessions WHERE id=?', (session_id,)).fetchone()
    rows = con.execute('SELECT roll_no, name, datetime(marked_ts, "unixepoch", "localtime") AS marked_at FROM attendance WHERE session_id=? ORDER BY marked_ts', (session_id,)).fetchall()
  return render_template('export.html', s=s, rows=rows)

@app.get('/export_csv/<int:session_id>.csv')
@role_required('teacher')
def export_csv(session_id):
  with db() as con:
    rows = con.execute('SELECT roll_no, name, marked_ts FROM attendance WHERE session_id=? ORDER BY marked_ts', (session_id,)).fetchall()
  out = io.StringIO()
  w = csv.writer(out)
  w.writerow(['roll_no','name','marked_at_unix'])
  for r in rows:
    w.writerow([r['roll_no'], r['name'], r['marked_ts']])
  mem = io.BytesIO(out.getvalue().encode()); mem.seek(0)
  return send_file(mem, mimetype='text/csv', as_attachment=True, download_name=f'session_{session_id}.csv')

@app.get('/dashboard')
@role_required('teacher')
def dashboard():
  with db() as con:
    total_sessions = con.execute('SELECT COUNT(*) AS c FROM sessions').fetchone()['c']
    total_att = con.execute('SELECT COUNT(*) AS c FROM attendance').fetchone()['c']
    recent = con.execute('''
      SELECT s.id, s.course, s.room, s.start_ts, s.end_ts,
             (SELECT COUNT(*) FROM attendance a WHERE a.session_id = s.id) AS present
      FROM sessions s ORDER BY s.id DESC LIMIT 12
    ''').fetchall()
    sparkline = list(reversed([r['present'] for r in recent])) if recent else []
    spark_max = max(sparkline) if sparkline else 1
    per_student = con.execute('''
      SELECT roll_no, name, COUNT(*) AS presents
      FROM attendance GROUP BY roll_no, name
      ORDER BY presents DESC LIMIT 20
    ''').fetchall()
    risk = []
    if total_sessions >= 3:
      risk = con.execute('''
        SELECT roll_no, name, COUNT(*) AS presents
        FROM attendance
        GROUP BY roll_no, name
        HAVING presents <= 1
        ORDER BY presents ASC
        LIMIT 20
      ''').fetchall()
    heat = [[0,0,0] for _ in range(7)]
    sess_rows = con.execute('SELECT id, start_ts FROM sessions').fetchall()
    for srow in sess_rows:
      c = con.execute('SELECT COUNT(*) AS c FROM attendance WHERE session_id=?', (srow['id'],)).fetchone()['c']
      dt = datetime.fromtimestamp(srow['start_ts']); wd = dt.weekday(); hr = dt.hour
      if 6 <= hr < 12: sl = 0
      elif 12 <= hr < 17: sl = 1
      elif 17 <= hr < 22: sl = 2
      else: sl = 0
      heat[wd][sl] += c
    heat_flat = [v for row in heat for v in row]
    heat_max = max(heat_flat) if heat_flat else 1
    heat_norm = [[(v/heat_max) if heat_max else 0 for v in row] for row in heat]
  return render_template('dashboard.html',
                         total_sessions=total_sessions,
                         total_att=total_att,
                         recent=recent,
                         per_student=per_student,
                         risk=risk,
                         sparkline=sparkline,
                         spark_max=spark_max,
                         heat_norm=heat_norm)

@app.get('/me')
@login_required
def me():
  if session.get('role') != 'student':
    return redirect(url_for('dashboard'))
  roll_no = session.get('roll_no')
  stats = compute_student_stats(roll_no)
  return render_template('me.html', student_name=session.get('full_name'), roll_no=roll_no, stats=stats)

@app.get('/me/export.csv')
@login_required
def me_export_csv():
  if session.get('role') != 'student':
    return redirect(url_for('dashboard'))
  roll_no = session.get('roll_no')
  stats = compute_student_stats(roll_no)
  out = io.StringIO()
  w = csv.writer(out)
  w.writerow(['session_id', 'course', 'room', 'start_ts', 'marked_ts', 'marked_at_local'])
  for r in stats['rows']:
    marked_local = datetime.fromtimestamp(r['marked_ts']).strftime('%Y-%m-%d %H:%M:%S')
    w.writerow([r['session_id'], r['course'], r['room'], r['start_ts'], r['marked_ts'], marked_local])
  mem = io.BytesIO(out.getvalue().encode()); mem.seek(0)
  return send_file(mem, mimetype='text/csv', as_attachment=True, download_name=f'{roll_no}_attendance.csv')

@app.get('/me/password')
@login_required
def me_password_form():
  if session.get('role') != 'student':
    return redirect(url_for('dashboard'))
  return render_template('change_password.html')

@app.post('/me/password')
@login_required
def me_password_update():
  if session.get('role') != 'student':
    return redirect(url_for('dashboard'))
  old = request.form.get('old_password') or ''
  new = request.form.get('new_password') or ''
  if len(new) < 6:
    flash('New password must be at least 6 characters.', 'error')
    return redirect(url_for('me_password_form'))
  with db() as con:
    user = con.execute('SELECT * FROM users WHERE id=?', (session['user_id'],)).fetchone()
    if not user or not check_password_hash(user['password_hash'], old):
      flash('Old password is incorrect.', 'error')
      return redirect(url_for('me_password_form'))
    con.execute('UPDATE users SET password_hash=? WHERE id=?', (generate_password_hash(new), session['user_id']))
  flash('Password changed successfully.', 'ok')
  return redirect(url_for('me'))

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5001, debug=True)