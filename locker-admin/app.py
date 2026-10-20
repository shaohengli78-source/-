import csv
import hmac
import io
import os
import re
import secrets
from datetime import date
import sqlite3
from datetime import timedelta
from functools import wraps
from pathlib import Path

import click
from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

SCHEMA = '''
CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS students(id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS authorized(student_id TEXT PRIMARY KEY REFERENCES students(id));
CREATE TABLE IF NOT EXISTS card_requests(request_id TEXT PRIMARY KEY, command_id TEXT UNIQUE REFERENCES commands(id), student_id TEXT REFERENCES students(id));
CREATE TABLE IF NOT EXISTS lockers(id INTEGER PRIMARY KEY, label TEXT UNIQUE NOT NULL, student_id TEXT REFERENCES students(id), since TEXT);
CREATE TABLE IF NOT EXISTS usage(id INTEGER PRIMARY KEY, locker_id INTEGER REFERENCES lockers(id), student_id TEXT REFERENCES students(id), started TEXT DEFAULT CURRENT_TIMESTAMP, ended TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_locker ON usage(locker_id) WHERE ended IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS one_active_student ON usage(student_id) WHERE ended IS NULL;
CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY, locker_id INTEGER REFERENCES lockers(id), action TEXT NOT NULL, reason TEXT NOT NULL, actor TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created TEXT DEFAULT CURRENT_TIMESTAMP, expires TEXT NOT NULL, finished TEXT, detail TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS one_pending_command ON commands(locker_id) WHERE status='pending';
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS failures(key TEXT PRIMARY KEY, attempts INTEGER NOT NULL, until INTEGER NOT NULL);
'''


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY'), DATABASE=os.environ.get('DATABASE_PATH', str(Path(app.instance_path) / 'locker.sqlite3')), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict', SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '1') == '1', PERMANENT_SESSION_LIFETIME=timedelta(hours=2), MAX_CONTENT_LENGTH=32768, STUDENT_ID_PATTERN=os.environ.get('STUDENT_ID_PATTERN', r'[0-9]{8,12}'), INGEST_TOKEN=os.environ.get('INGEST_TOKEN', ''), DEVICE_TOKEN=os.environ.get('DEVICE_TOKEN', ''))
    if test_config:
        app.config.update(test_config)
    if not app.config['SECRET_KEY'] or len(app.config['SECRET_KEY']) < 32:
        raise RuntimeError('SECRET_KEY 必须配置为至少 32 位随机字符串')
    re.compile(app.config['STUDENT_ID_PATTERN'])
    Path(app.config['DATABASE']).parent.mkdir(parents=True, exist_ok=True)

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DATABASE'], timeout=15)
            g.db.row_factory = sqlite3.Row
            g.db.execute('PRAGMA foreign_keys=ON')
        return g.db

    @app.teardown_appcontext
    def close(_):
        if 'db' in g:
            g.db.close()

    with app.app_context():
        db().executescript(SCHEMA)
        db().execute('PRAGMA journal_mode=WAL')
        bootstrap = os.environ.get('BOOTSTRAP_ADMIN_HASH')
        if bootstrap:
            db().execute('INSERT OR IGNORE INTO admins(username,password) VALUES(?,?)', (os.environ.get('BOOTSTRAP_ADMIN_USER', 'admin'), bootstrap))
        db().commit()

    def audit(actor, action, detail):
        db().execute('INSERT INTO audit(actor,action,detail) VALUES(?,?,?)', (actor, action, detail))

    def expire():
        db().execute("UPDATE commands SET status='expired',finished=CURRENT_TIMESTAMP,detail='设备未在有效期内确认；需人工核对' WHERE status='pending' AND expires<=CURRENT_TIMESTAMP")
        db().commit()

    def admin(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not session.get('admin'):
                if request.path.startswith('/api/'):
                    abort(401)
                return redirect(url_for('login'))
            if request.method != 'GET' and not hmac.compare_digest(str(session.get('csrf', '')), request.headers.get('X-CSRF-Token', '')):
                abort(403)
            return fn(*args, **kwargs)
        return wrapped

    def token(name):
        def decorator(fn):
            @wraps(fn)
            def wrapped(*args, **kwargs):
                expected = app.config[name]
                if not expected or not hmac.compare_digest(request.headers.get('Authorization', ''), 'Bearer ' + expected):
                    abort(401)
                return fn(*args, **kwargs)
            return wrapped
        return decorator

    def data():
        value = request.get_json(silent=True)
        if not isinstance(value, dict):
            abort(400, '需要 JSON 对象')
        return value

    def text(value, limit, required=True):
        if not isinstance(value, str) or len(value.strip()) > limit or (required and not value.strip()):
            abort(400, '字段为空或长度不正确')
        return value.strip()

    def student(body):
        sid = text(body.get('student_id'), 32)
        if not re.fullmatch(app.config['STUDENT_ID_PATTERN'], sid, flags=re.ASCII):
            abort(400, '学号格式不符合规则')
        name = text(body.get('name', ''), 40, False)
        phone = text(body.get('phone', ''), 24, False)
        if phone and not re.fullmatch(r'[0-9+() -]{6,24}', phone):
            abort(400, '联系电话格式错误')
        db().execute("INSERT INTO students(id,name,phone) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET name=CASE WHEN excluded.name<>'' THEN excluded.name ELSE students.name END,phone=CASE WHEN excluded.phone<>'' THEN excluded.phone ELSE students.phone END", (sid, name, phone))
        return sid

    @app.after_request
    def headers(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    @app.errorhandler(429)
    def error(exc):
        return jsonify(error=str(exc.description)), exc.code

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        session.setdefault('csrf', secrets.token_hex(24))
        error = None
        if request.method == 'POST':
            if not hmac.compare_digest(session['csrf'], request.form.get('csrf', '')):
                abort(403)
            username = request.form.get('username', '')[:100]
            # SQLite 持久限流，避免通过重启或多进程绕过。反向代理无需信任任意 X-Forwarded-For。
            key = 'login:' + username
            db().execute('BEGIN IMMEDIATE')
            row = db().execute("SELECT * FROM failures WHERE key=? AND until>unixepoch()", (key,)).fetchone()
            if row and row['attempts'] >= 5:
                db().rollback()
                abort(429, '尝试过于频繁，请 15 分钟后重试')
            user = db().execute('SELECT * FROM admins WHERE username=?', (username,)).fetchone()
            if user and check_password_hash(user['password'], request.form.get('password', '')):
                db().execute('DELETE FROM failures WHERE key=?', (key,))
                audit(username, 'login', '管理员登录')
                db().commit()
                session.clear()
                session.update(admin=username, csrf=secrets.token_hex(24))
                session.permanent = True
                return redirect('/')
            db().execute("INSERT INTO failures VALUES(?,1,unixepoch()+900) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN until<=unixepoch() THEN 1 ELSE attempts+1 END,until=CASE WHEN until<=unixepoch() THEN unixepoch()+900 ELSE until END", (key,))
            db().commit()
            error = '用户名或密码错误'
        return render_template('login.html', error=error)

    @app.get('/')
    @admin
    def index():
        return render_template('index.html', pattern=app.config['STUDENT_ID_PATTERN'])

    @app.post('/api/password')
    @admin
    def change_password():
        body = data()
        old = text(body.get('old'), 200)
        new = text(body.get('new'), 200)
        if len(new) < 12:
            abort(400, '新密码至少 12 位')
        user = db().execute('SELECT password FROM admins WHERE username=?', (session['admin'],)).fetchone()
        # 密码修改也使用持久限流。
        key = 'password:' + session['admin']
        db().execute('BEGIN IMMEDIATE')
        if db().execute('SELECT 1 FROM failures WHERE key=? AND attempts>=5 AND until>unixepoch()', (key,)).fetchone():
            abort(429, '尝试过于频繁，请 15 分钟后重试')
        if not check_password_hash(user['password'], old):
            db().execute("INSERT INTO failures VALUES(?,1,unixepoch()+900) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN until<=unixepoch() THEN 1 ELSE attempts+1 END,until=CASE WHEN until<=unixepoch() THEN unixepoch()+900 ELSE until END", (key,))
            db().commit()
            abort(403, '原密码错误')
        db().execute('UPDATE admins SET password=? WHERE username=?', (generate_password_hash(new), session['admin']))
        db().execute('DELETE FROM failures WHERE key=?', (key,))
        audit(session['admin'], 'password_change', '管理员修改密码')
        db().commit()
        session.clear()
        return jsonify(ok=True)

    @app.post('/api/logout')
    @admin
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.get('/healthz')
    def health():
        db().execute('SELECT 1').fetchone()
        return jsonify(ok=True)

    def period():
        start, end = request.args.get('from', ''), request.args.get('to', '')
        try:
            if start: date.fromisoformat(start)
            if end: date.fromisoformat(end)
            if start and end and start > end: raise ValueError()
        except ValueError:
            abort(400, '日期区间无效')
        return start or '0001-01-01', end or '9999-12-31'

    @app.get('/api/state')
    @admin
    def state():
        expire()
        queries = {
            'lockers': 'SELECT l.*,s.name,s.phone FROM lockers l LEFT JOIN students s ON s.id=l.student_id ORDER BY l.id',
            'students': 'SELECT s.*,EXISTS(SELECT 1 FROM authorized a WHERE a.student_id=s.id) AS authorized,COUNT(u.id) AS uses FROM students s LEFT JOIN usage u ON u.student_id=s.id GROUP BY s.id ORDER BY uses DESC,s.id',
            'usage': 'SELECT u.*,l.label,s.name FROM usage u JOIN lockers l ON l.id=u.locker_id JOIN students s ON s.id=u.student_id ORDER BY u.id DESC',
            'commands': 'SELECT c.*,l.label FROM commands c JOIN lockers l ON l.id=c.locker_id ORDER BY c.created DESC',
            'audit': 'SELECT * FROM audit ORDER BY id DESC LIMIT 500'
        }
        result = {k: [dict(r) for r in db().execute(q)] for k, q in queries.items()}
        start, end = period()
        result['statistics'] = [dict(r) for r in db().execute("SELECT s.id,s.name,s.phone,COUNT(u.id) AS uses FROM students s LEFT JOIN usage u ON u.student_id=s.id AND date(u.started,'+8 hours') BETWEEN ? AND ? GROUP BY s.id ORDER BY uses DESC,s.id", (start,end))]
        return jsonify(result)

    @app.post('/api/students')
    @admin
    def add_student():
        body = data()
        sid = student(body)
        if body.get('authorized', True) is True:
            db().execute('INSERT OR IGNORE INTO authorized VALUES(?)', (sid,))
        else:
            db().execute('DELETE FROM authorized WHERE student_id=?', (sid,))
        audit(session['admin'], 'student_save', sid)
        db().commit()
        return jsonify(ok=True)

    @app.post('/api/external/students')
    @token('INGEST_TOKEN')
    def ingest():
        sid = student(data())
        audit('external', 'student_ingest', sid)
        db().commit()
        return jsonify(ok=True, student_id=sid)

    @app.post('/api/lockers')
    @admin
    def add_locker():
        label = text(data().get('label'), 40)
        try:
            db().execute('INSERT INTO lockers(label) VALUES(?)', (label,))
            audit(session['admin'], 'locker_add', label)
            db().commit()
        except sqlite3.IntegrityError:
            db().rollback()
            abort(409, '柜子编号已存在')
        return jsonify(ok=True)

    @app.post('/api/lockers/<int:lid>/assign')
    @admin
    def assign(lid):
        body = data()
        expire()
        db().execute('BEGIN IMMEDIATE')
        locker = db().execute('SELECT * FROM lockers WHERE id=?', (lid,)).fetchone()
        if not locker:
            abort(404)
        if locker['student_id'] or db().execute("SELECT 1 FROM commands WHERE locker_id=? AND status='pending'", (lid,)).fetchone():
            abort(409, '柜子已占用或有待执行指令')
        sid = text(body.get('student_id'), 32)
        if not db().execute('SELECT 1 FROM authorized WHERE student_id=?', (sid,)).fetchone():
            abort(403, '学号未授权，请先登记学生')
        record = db().execute('SELECT * FROM students WHERE id=?', (sid,)).fetchone()
        if not record['name'] or not record['phone']:
            abort(400, '分配柜子前请补全姓名和联系电话')
        if db().execute("SELECT 1 FROM card_requests r JOIN commands c ON c.id=r.command_id WHERE r.student_id=? AND c.status='pending'", (sid,)).fetchone():
            abort(409, '该学生正在刷卡申请柜子')
        try:
            db().execute('INSERT INTO usage(locker_id,student_id) VALUES(?,?)', (lid, sid))
            db().execute('UPDATE lockers SET student_id=?,since=CURRENT_TIMESTAMP WHERE id=?', (sid, lid))
            audit(session['admin'], 'assign', f'{locker["label"]} / {sid}')
            db().commit()
        except sqlite3.IntegrityError:
            db().rollback()
            abort(409, '该学生已有使用中的柜子')
        return jsonify(ok=True)

    @app.post('/api/lockers/<int:lid>/command')
    @admin
    def command(lid):
        body = data()
        action = body.get('action')
        if action not in ('unlock', 'reset'):
            abort(400, '无效操作')
        reason = text(body.get('reason'), 300)
        expire()
        db().execute('BEGIN IMMEDIATE')
        locker = db().execute('SELECT * FROM lockers WHERE id=?', (lid,)).fetchone()
        if not locker:
            abort(404)
        if body.get('confirm') != locker['label']:
            abort(400, '确认编号与柜子不一致')
        user = db().execute('SELECT password FROM admins WHERE username=?', (session['admin'],)).fetchone()
        key = 'control:' + session['admin']
        blocked = db().execute('SELECT 1 FROM failures WHERE key=? AND attempts>=5 AND until>unixepoch()', (key,)).fetchone()
        if blocked:
            abort(429, '密码验证过于频繁，请 15 分钟后重试')
        if not check_password_hash(user['password'], str(body.get('password', ''))):
            db().execute("INSERT INTO failures VALUES(?,1,unixepoch()+900) ON CONFLICT(key) DO UPDATE SET attempts=CASE WHEN until<=unixepoch() THEN 1 ELSE attempts+1 END,until=CASE WHEN until<=unixepoch() THEN unixepoch()+900 ELSE until END", (key,))
            db().commit()
            abort(403, '管理员密码错误')
        if not app.config['DEVICE_TOKEN']:
            abort(409, '设备接口尚未配置，无法下发指令')
        cid = secrets.token_hex(16)
        try:
            db().execute("INSERT INTO commands(id,locker_id,action,reason,actor,expires) VALUES(?,?,?,?,?,datetime('now','+5 minutes'))", (cid, lid, action, reason, session['admin']))
            db().execute('DELETE FROM failures WHERE key=?', (key,))
            audit(session['admin'], action + '_requested', f'{locker["label"]} / {reason} / {cid}')
            db().commit()
        except sqlite3.IntegrityError:
            db().rollback()
            abort(409, '该柜子已有待执行指令，请勿重复提交')
        return jsonify(ok=True, command_id=cid), 202

    @app.post('/api/device/store')
    @token('DEVICE_TOKEN')
    def card_store():
        body = data()
        sid = text(body.get('student_id'), 32)
        rid = text(body.get('request_id'), 80)
        lid = body.get('locker_id')
        if type(lid) is not int:
            abort(400, 'locker_id 必须是整数')
        expire()
        db().execute('BEGIN IMMEDIATE')
        prior = db().execute('SELECT r.student_id,c.* FROM card_requests r JOIN commands c ON c.id=r.command_id WHERE r.request_id=?', (rid,)).fetchone()
        if prior:
            if prior['student_id'] != sid or prior['locker_id'] != lid:
                abort(409, 'request_id 已用于其他请求')
            return jsonify(command_id=prior['id'], status=prior['status'])
        record = db().execute('SELECT s.* FROM students s JOIN authorized a ON a.student_id=s.id WHERE s.id=?', (sid,)).fetchone()
        if not record:
            abort(403, '学号不在授权名单内')
        if not record['name'] or not record['phone']:
            abort(409, '请管理员先补全姓名和电话')
        locker = db().execute('SELECT * FROM lockers WHERE id=?', (lid,)).fetchone()
        if not locker:
            abort(404)
        if locker['student_id']:
            abort(409, '柜子已占用')
        if db().execute('SELECT 1 FROM usage WHERE student_id=? AND ended IS NULL', (sid,)).fetchone() or db().execute("SELECT 1 FROM card_requests r JOIN commands c ON c.id=r.command_id WHERE r.student_id=? AND c.status='pending'", (sid,)).fetchone():
            abort(409, '学生已有占用或申请中的柜子')
        cid = secrets.token_hex(16)
        try:
            db().execute("INSERT INTO commands(id,locker_id,action,reason,actor,expires) VALUES(?,?,'store','学生刷卡存入',?,datetime('now','+5 minutes'))", (cid,lid,sid))
            db().execute('INSERT INTO card_requests VALUES(?,?,?)', (rid,cid,sid))
            audit('device', 'card_store', f'{sid} / {lid} / {cid}')
            db().commit()
        except sqlite3.IntegrityError:
            db().rollback()
            abort(409, '柜子已有待执行指令')
        return jsonify(command_id=cid, status='pending'), 202

    @app.post('/api/device/release')
    @token('DEVICE_TOKEN')
    def release():
        body = data()
        # 设备必须先验证密码并确认取完/关门。绑定本次使用 ID，防止旧消息释放新占用。
        uid = body.get('usage_id')
        if type(uid) is not int:
            abort(400, 'usage_id 必须是整数')
        db().execute('BEGIN IMMEDIATE')
        usage = db().execute('SELECT * FROM usage WHERE id=?', (uid,)).fetchone()
        if not usage:
            abort(404)
        if usage['ended']:
            return jsonify(ok=True, duplicate=True)
        if db().execute("SELECT 1 FROM commands WHERE locker_id=? AND status='pending'", (usage['locker_id'],)).fetchone():
            abort(409, '有未完成管理员指令，请稍后重试')
        db().execute('UPDATE usage SET ended=CURRENT_TIMESTAMP WHERE id=?', (uid,))
        db().execute('UPDATE lockers SET student_id=NULL,since=NULL WHERE id=?', (usage['locker_id'],))
        audit('device', 'release', str(uid))
        db().commit()
        return jsonify(ok=True)

    @app.get('/api/device/lockers/<int:lid>')
    @token('DEVICE_TOKEN')
    def device_state(lid):
        record = db().execute('SELECT l.id,l.label,l.student_id,s.name,s.phone,u.id AS usage_id FROM lockers l LEFT JOIN students s ON s.id=l.student_id LEFT JOIN usage u ON u.locker_id=l.id AND u.ended IS NULL WHERE l.id=?', (lid,)).fetchone()
        if not record:
            abort(404)
        return jsonify(dict(record))

    @app.get('/api/device/commands')
    @token('DEVICE_TOKEN')
    def poll():
        expire()
        return jsonify(commands=[dict(r) for r in db().execute("SELECT c.id,c.locker_id,l.label,c.action,c.expires FROM commands c JOIN lockers l ON l.id=c.locker_id WHERE c.status='pending' ORDER BY c.created")])

    @app.post('/api/device/commands/<cid>/ack')
    @token('DEVICE_TOKEN')
    def ack(cid):
        body = data()
        if type(body.get('success')) is not bool:
            abort(400, 'success 必须为布尔值')
        detail = text(body.get('detail', ''), 300, False)
        expire()
        db().execute('BEGIN IMMEDIATE')
        cmd = db().execute('SELECT * FROM commands WHERE id=?', (cid,)).fetchone()
        if not cmd:
            abort(404)
        status = 'succeeded' if body['success'] else 'failed'
        if cmd['status'] != 'pending':
            if cmd['status'] == status:
                return jsonify(ok=True, duplicate=True)
            abort(409, '指令已结束或过期，需人工核对状态')
        db().execute('UPDATE commands SET status=?,detail=?,finished=CURRENT_TIMESTAMP WHERE id=?', (status, detail, cid))
        if body['success'] and cmd['action'] == 'store':
            sid = db().execute('SELECT student_id FROM card_requests WHERE command_id=?', (cid,)).fetchone()['student_id']
            db().execute('INSERT INTO usage(locker_id,student_id) VALUES(?,?)', (cmd['locker_id'], sid))
            db().execute('UPDATE lockers SET student_id=?,since=CURRENT_TIMESTAMP WHERE id=?', (sid,cmd['locker_id']))
        if body['success'] and cmd['action'] == 'reset':
            db().execute('UPDATE usage SET ended=CURRENT_TIMESTAMP WHERE locker_id=? AND ended IS NULL', (cmd['locker_id'],))
            db().execute('UPDATE lockers SET student_id=NULL,since=NULL WHERE id=?', (cmd['locker_id'],))
        audit('device', 'command_ack', f'{cid} / {status} / {detail}')
        db().commit()
        return jsonify(ok=True)

    @app.get('/api/export/<kind>')
    @admin
    def export(kind):
        queries = {
            'statistics': ('学号,姓名,联系电话,使用次数', 'SELECT s.id,s.name,s.phone,COUNT(u.id) FROM students s LEFT JOIN usage u ON s.id=u.student_id GROUP BY s.id'),
            'usage': ('记录ID,柜子ID,学号,开始时间UTC,结束时间UTC', 'SELECT * FROM usage ORDER BY id DESC'),
            'audit': ('记录ID,操作者,操作,详情,时间UTC', 'SELECT * FROM audit ORDER BY id DESC')
        }
        if kind not in queries:
            abort(404)
        header, query = queries[kind]
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(header.split(','))
        args = ()
        if kind == 'statistics':
            args = period()
            query = "SELECT s.id,s.name,s.phone,COUNT(u.id) FROM students s LEFT JOIN usage u ON s.id=u.student_id AND date(u.started,'+8 hours') BETWEEN ? AND ? GROUP BY s.id"
        for row in db().execute(query, args):
            writer.writerow([("'" + str(v)) if str(v).lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else v for v in row])
        audit(session['admin'], 'export', kind)
        db().commit()
        return Response('\ufeff' + out.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename="{kind}.csv"'})

    @app.cli.command('create-admin')
    @click.argument('username')
    @click.password_option(confirmation_prompt=True)
    def create_admin(username, password):
        if len(password) < 12:
            raise click.ClickException('密码至少 12 位')
        try:
            db().execute('INSERT INTO admins(username,password) VALUES(?,?)', (username, generate_password_hash(password)))
            db().commit()
        except sqlite3.IntegrityError:
            raise click.ClickException('管理员已存在')
        click.echo('管理员已创建')

    @app.cli.command('reset-admin-password')
    @click.argument('username')
    @click.password_option(confirmation_prompt=True)
    def reset_password(username, password):
        if len(password) < 12:
            raise click.ClickException('密码至少 12 位')
        result = db().execute('UPDATE admins SET password=? WHERE username=?', (generate_password_hash(password), username))
        if not result.rowcount:
            raise click.ClickException('管理员不存在')
        audit('console', 'password_reset', username)
        db().commit()
        click.echo('密码已更新；请轮换 SECRET_KEY 撤销现有会话')

    return app
