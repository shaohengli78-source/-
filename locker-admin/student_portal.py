"""Card-bound, single-use QR student sessions. Demo data never reaches real devices."""
import base64
import hashlib
import hmac
import io
import os
import re
import secrets
import sqlite3
import time
from functools import wraps

import qrcode
from flask import abort, g, jsonify, redirect, render_template, request, session


def register_student_portal(app, db, admin, audit, data, expire, device_auth):
    app.config.setdefault('PUBLIC_BASE_URL', os.environ.get('PUBLIC_BASE_URL', 'https://locker-admin-production.up.railway.app'))
    with app.app_context():
        db().executescript('''
        CREATE TABLE IF NOT EXISTS student_access(student_id TEXT PRIMARY KEY REFERENCES students(id),version INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS campus_cards(card_uid TEXT PRIMARY KEY,student_id TEXT UNIQUE NOT NULL REFERENCES students(id));
        CREATE TABLE IF NOT EXISTS login_tickets(token_hash TEXT PRIMARY KEY,student_id TEXT,version INTEGER,kind TEXT NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS ticket_expiry ON login_tickets(expires);
        CREATE TABLE IF NOT EXISTS student_demos(id TEXT PRIMARY KEY,locker_id INTEGER,started TEXT,expires INTEGER NOT NULL);
        ''')
        db().commit()

    def check_csrf():
        expected = session.get('csrf')
        actual = request.headers.get('X-CSRF-Token', '')
        if not expected or not hmac.compare_digest(expected, actual):
            abort(403, '页面已过期，请刷新重试')

    def card_uid(value):
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9:_-]{4,128}', value):
            abort(400, '卡片编号需为4–128位字母、数字、冒号、下划线或短横线')
        return value.upper()

    def grant(kind, sid=None, version=None):
        value = secrets.token_urlsafe(32)
        deadline = int(time.time()) + 60
        db().execute('DELETE FROM login_tickets WHERE expires<=?', (int(time.time()),))
        db().execute('DELETE FROM student_demos WHERE expires<=?', (int(time.time()),))
        if sid:
            db().execute('DELETE FROM login_tickets WHERE student_id=?', (sid,))
        db().execute('INSERT INTO login_tickets(token_hash,student_id,version,kind,expires) VALUES(?,?,?,?,?)', (hashlib.sha256(value.encode()).hexdigest(), sid, version, kind, deadline))
        # Fragment is never sent in HTTP requests, server access logs or referrers.
        link = app.config['PUBLIC_BASE_URL'].rstrip('/') + '/student/login#ticket=' + value
        image = qrcode.make(link)
        out = io.BytesIO()
        image.save(out, format='PNG')
        return dict(login_url=link, expires_at=deadline, expires_in=60, qr_image='data:image/png;base64,' + base64.b64encode(out.getvalue()).decode(), demo=kind=='demo')

    def student_required(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            g.student_demo = None
            g.student_account = None
            if session.get('demo_id'):
                g.student_demo = db().execute('SELECT * FROM student_demos WHERE id=? AND expires>?', (session['demo_id'], int(time.time()))).fetchone()
            elif session.get('student_id'):
                g.student_account = db().execute('SELECT a.student_id,a.version,s.name FROM student_access a JOIN students s ON s.id=a.student_id JOIN authorized z ON z.student_id=a.student_id WHERE a.student_id=? AND a.version=?', (session['student_id'], session.get('student_version'))).fetchone()
            if not g.student_demo and not g.student_account:
                if request.path.startswith('/api/'):
                    abort(401, '登录已过期或授权已撤销，请重新刷卡扫码')
                return redirect('/student/login')
            if request.method != 'GET':
                check_csrf()
            return fn(*args, **kwargs)
        return wrapped

    @app.get('/')
    def entrance():
        return render_template('entrance.html')

    @app.get('/student/login')
    def student_login():
        session.setdefault('csrf', secrets.token_hex(24))
        return render_template('student_login.html')

    @app.post('/api/device/login-qr')
    @device_auth
    def issue_login_qr():
        uid = card_uid(data().get('card_uid'))
        db().execute('BEGIN IMMEDIATE')
        record = db().execute('SELECT a.student_id,a.version FROM campus_cards c JOIN student_access a ON a.student_id=c.student_id JOIN authorized z ON z.student_id=c.student_id WHERE c.card_uid=?', (uid,)).fetchone()
        if not record:
            abort(403, '校园卡未绑定或学生未授权，请联系管理员')
        result = grant('student', record['student_id'], record['version'])
        audit('device', 'student_qr_issued', record['student_id'])
        db().commit()
        return jsonify(result), 201

    @app.post('/api/student/demo-qr')
    def demo_qr():
        check_csrf()
        now = int(time.time())
        if now - session.get('last_demo_qr', 0) < 3:
            abort(429, '请稍等几秒再模拟刷卡')
        session['last_demo_qr'] = now
        db().execute('BEGIN IMMEDIATE')
        # Public demo ticket grants access only to an isolated synthetic session.
        result = grant('demo')
        db().commit()
        return jsonify(result), 201

    @app.post('/api/student/exchange')
    def exchange():
        check_csrf()
        value = data().get('ticket')
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value):
            abort(400, '二维码无效，请重新刷卡')
        digest = hashlib.sha256(value.encode()).hexdigest()
        db().execute('BEGIN IMMEDIATE')
        ticket = db().execute('SELECT * FROM login_tickets WHERE token_hash=? AND used=0 AND expires>?', (digest,int(time.time()))).fetchone()
        if not ticket:
            abort(401, '二维码已过期或已使用，请重新刷卡')
        if ticket['kind']=='student':
            record = db().execute('SELECT 1 FROM student_access a JOIN authorized z ON z.student_id=a.student_id WHERE a.student_id=? AND a.version=?', (ticket['student_id'], ticket['version'])).fetchone()
            if not record:
                abort(403, '授权或卡片绑定已变更，请重新刷卡')
            new_session = dict(student_id=ticket['student_id'], student_version=ticket['version'])
            audit('student:' + ticket['student_id'], 'student_qr_login', '一次性校园卡二维码登录')
        else:
            demo_id = secrets.token_hex(24)
            db().execute('INSERT INTO student_demos(id,expires) VALUES(?,?)', (demo_id,int(time.time())+7200))
            new_session = dict(demo_id=demo_id)
        db().execute('UPDATE login_tickets SET used=1 WHERE token_hash=?', (digest,))
        db().commit()
        session.clear()
        session.update(**new_session, csrf=secrets.token_hex(24))
        session.permanent = True
        return jsonify(ok=True, redirect='/student')

    @app.get('/student')
    @student_required
    def student_home():
        student = g.student_account or {'student_id':'DEMO-001','name':'体验学生'}
        return render_template('student.html', student=student, demo=bool(g.student_demo))

    @app.get('/api/student/state')
    @student_required
    def student_state():
        if g.student_demo:
            row = g.student_demo
            own = {'id':row['locker_id'],'label':f'模拟柜 A-0{row["locker_id"]}','started':row['started']} if row['locker_id'] else None
            available = [{'id':i,'label':f'模拟柜 A-0{i}'} for i in range(1,5) if i!=row['locker_id']]
            return jsonify(demo=True,student={'id':'DEMO-001','name':'体验学生'},own=own,pending=None,own_command=None,available=available,can_use_new=not own)
        expire()
        sid = session['student_id']
        db().execute('BEGIN')
        own = db().execute('SELECT l.id,l.label,u.id AS usage_id,u.started FROM lockers l JOIN usage u ON u.locker_id=l.id AND u.ended IS NULL WHERE u.student_id=?', (sid,)).fetchone()
        pending = db().execute("SELECT l.label,c.expires FROM card_requests r JOIN commands c ON c.id=r.command_id JOIN lockers l ON l.id=c.locker_id WHERE r.student_id=? AND c.status='pending'", (sid,)).fetchone()
        available = [dict(r) for r in db().execute("SELECT l.id,l.label FROM lockers l WHERE l.student_id IS NULL AND NOT EXISTS(SELECT 1 FROM usage u WHERE u.locker_id=l.id AND u.ended IS NULL) AND NOT EXISTS(SELECT 1 FROM commands c WHERE c.locker_id=l.id AND c.status='pending') ORDER BY l.id")]
        own_command = db().execute("SELECT c.action,c.status FROM commands c JOIN usage u ON u.locker_id=c.locker_id AND u.ended IS NULL WHERE u.student_id=? AND c.status='pending'", (sid,)).fetchone()
        db().commit()
        return jsonify(demo=False,student={'id':sid,'name':g.student_account['name']},own=dict(own) if own else None,pending=dict(pending) if pending else None,own_command=dict(own_command) if own_command else None,available=available,can_use_new=not own and not pending)

    @app.post('/api/student/demo-use')
    @student_required
    def demo_use():
        if not g.student_demo:
            abort(403, '仅体验模式允许模拟操作')
        lid = data().get('locker_id')
        if type(lid) is not int or lid not in range(1,5):
            abort(400, '请选择模拟柜子')
        db().execute('BEGIN IMMEDIATE')
        changed = db().execute('UPDATE student_demos SET locker_id=?,started=CURRENT_TIMESTAMP WHERE id=? AND locker_id IS NULL', (lid,session['demo_id']))
        if not changed.rowcount:
            abort(409, '每人只能使用一个柜子，请先结束当前使用')
        db().commit()
        return jsonify(ok=True)

    @app.post('/api/student/demo-release')
    @student_required
    def demo_release():
        if not g.student_demo:
            abort(403, '仅体验模式允许模拟操作')
        db().execute('UPDATE student_demos SET locker_id=NULL,started=NULL WHERE id=?', (session['demo_id'],))
        db().commit()
        return jsonify(ok=True)

    @app.post('/api/student/logout')
    @student_required
    def student_logout():
        session.clear()
        return jsonify(ok=True)

    @app.post('/api/students/<sid>/card')
    @admin
    def bind_card(sid):
        body = data()
        uid = card_uid(body.get('card_uid')) if body.get('card_uid') else None
        db().execute('BEGIN IMMEDIATE')
        if not db().execute('SELECT 1 FROM authorized WHERE student_id=?', (sid,)).fetchone():
            abort(400, '请先根据学校授权名单登记并授权学生')
        try:
            db().execute('DELETE FROM campus_cards WHERE student_id=?', (sid,))
            if uid:
                db().execute('INSERT INTO campus_cards VALUES(?,?)', (uid,sid))
            db().execute('INSERT INTO student_access(student_id) VALUES(?) ON CONFLICT(student_id) DO UPDATE SET version=version+1', (sid,))
            audit(session['admin'], 'campus_card_bind' if uid else 'campus_card_unbind', sid)
            db().commit()
        except sqlite3.IntegrityError:
            db().rollback()
            abort(409, '这张校园卡已绑定其他学生')
        return jsonify(ok=True)
