import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit, parse_qs
from test_app import setup, seed

DEVICE = {'Authorization':'Bearer device-test'}

def anonymous(app):
    c = app.test_client();c.get('/student/login')
    with c.session_transaction() as s: csrf=s['csrf']
    return c, {'X-CSRF-Token':csrf}

def token_from(r):
    assert r.status_code==201
    return parse_qs(urlsplit(r.json['login_url']).fragment)['ticket'][0]

def card_login(app,c,p,sid='20260001',card='CARD-A001'):
    assert p('/api/students/'+sid+'/card',{'card_uid':card}).status_code==200
    ticket=token_from(c.post('/api/device/login-qr',json={'card_uid':card},headers=DEVICE))
    student,headers=anonymous(app)
    assert student.post('/api/student/exchange',json={'ticket':ticket},headers=headers).status_code==200
    with student.session_transaction() as s: headers={'X-CSRF-Token':s['csrf']}
    return student,headers,ticket

def test_qr_single_use_and_role_isolation(setup):
    app,c,p=setup;seed(p)
    student,h,t=card_login(app,c,p)
    assert student.get('/student').status_code==200
    assert student.get('/api/state').status_code==401
    assert student.get('/api/export/statistics').status_code==401
    assert student.post('/api/lockers/1/command',json={},headers=h).status_code==401
    assert student.post('/api/students/20260001/card',json={'card_uid':'NEW-CARD'},headers=h).status_code==401
    another,headers=anonymous(app)
    assert another.post('/api/student/exchange',json={'ticket':t},headers=headers).status_code==401
    db=sqlite3.connect(app.config['DATABASE'])
    assert db.execute('SELECT token_hash FROM login_tickets').fetchone()[0]==hashlib.sha256(t.encode()).hexdigest()
    db.close()

def test_csrf_expiration_device_auth_and_no_self_registration(setup):
    app,c,p=setup;seed(p);p('/api/students/20260001/card',{'card_uid':'CARD-A001'})
    assert c.post('/api/device/login-qr',json={'card_uid':'CARD-A001'}).status_code==401
    assert c.post('/api/device/login-qr',json={'card_uid':'CARD-A001'},headers={'Authorization':'Bearer ingest-test'}).status_code==401
    t=token_from(c.post('/api/device/login-qr',json={'card_uid':'CARD-A001'},headers=DEVICE))
    student,h=anonymous(app)
    assert student.post('/api/student/exchange',json={'ticket':t}).status_code==403
    db=sqlite3.connect(app.config['DATABASE']);db.execute('UPDATE login_tickets SET expires=0');db.commit();db.close()
    assert student.post('/api/student/exchange',json={'ticket':t},headers=h).status_code==401
    assert student.post('/student/login',data={'student_id':'20260001'}).status_code==405
    assert student.get('/api/student/state?student_id=20260001').status_code==401

def test_private_view_only_own_state_and_pending_exclusion(setup):
    app,c,p=setup;seed(p);p('/api/lockers',{'label':'A-02'});p('/api/lockers',{'label':'A-03'})
    p('/api/students',{'student_id':'20260002','name':'Private Other Name','phone':'13912345678'})
    p('/api/lockers/2/assign',{'student_id':'20260002'})
    student,h,_=card_login(app,c,p)
    result=student.get('/api/student/state?student_id=20260002').json
    assert result['own'] is None and len(result['available'])==2
    assert 'Private Other Name' not in str(result) and '13912345678' not in str(result) and '20260002' not in str(result)
    r=c.post('/api/device/store',json={'student_id':'20260001','locker_id':1,'request_id':'one'},headers=DEVICE)
    assert r.status_code==202
    state=student.get('/api/student/state').json
    assert state['pending']['label']=='A-01' and state['can_use_new'] is False
    assert [l['id'] for l in state['available']]==[3]
    assert p('/api/lockers/3/assign',{'student_id':'20260001'}).status_code==409
    assert c.post('/api/device/commands/'+r.json['command_id']+'/ack',json={'success':True},headers=DEVICE).status_code==200
    state=student.get('/api/student/state').json
    assert state['own']['label']=='A-01' and state['can_use_new'] is False
    assert p('/api/lockers/3/assign',{'student_id':'20260001'}).status_code==409

def test_binding_and_authorization_revokes_sessions(setup):
    app,c,p=setup;seed(p)
    student,h,_=card_login(app,c,p)
    p('/api/students/20260001/card',{'card_uid':'NEW-CARD'})
    assert student.get('/api/student/state').status_code==401
    assert c.post('/api/device/login-qr',json={'card_uid':'CARD-A001'},headers=DEVICE).status_code==403
    t=token_from(c.post('/api/device/login-qr',json={'card_uid':'NEW-CARD'},headers=DEVICE))
    p('/api/students',{'student_id':'20260001','authorized':False})
    another,headers=anonymous(app)
    assert another.post('/api/student/exchange',json={'ticket':t},headers=headers).status_code==403
    assert c.post('/api/device/login-qr',json={'card_uid':'NEW-CARD'},headers=DEVICE).status_code==403

def test_same_qr_concurrent_exchange_once(setup):
    app,c,p=setup;seed(p);p('/api/students/20260001/card',{'card_uid':'CARD-A001'})
    t=token_from(c.post('/api/device/login-qr',json={'card_uid':'CARD-A001'},headers=DEVICE))
    clients=[anonymous(app),anonymous(app)]
    def use(pair):
        client,headers=pair
        return client.post('/api/student/exchange',json={'ticket':t},headers=headers).status_code
    with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(use,clients))
    assert sorted(results)==[200,401]

def test_demo_isolation_and_atomic_one_locker(setup):
    app,c,p=setup;seed(p)
    demo,headers=anonymous(app)
    t=token_from(demo.post('/api/student/demo-qr',json={},headers=headers))
    assert demo.post('/api/student/exchange',json={'ticket':t},headers=headers).status_code==200
    with demo.session_transaction() as s:
        h={'X-CSRF-Token':s['csrf']};demo_session=dict(s)
    clone=app.test_client()
    with clone.session_transaction() as s:s.update(demo_session)
    def use(pair):
        client,lid=pair
        return client.post('/api/student/demo-use',json={'locker_id':lid},headers=h).status_code
    with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(use,[(demo,1),(clone,2)]))
    assert sorted(results)==[200,409]
    assert demo.get('/api/student/state').json['can_use_new'] is False
    assert demo.get('/api/state').status_code==401
    assert demo.get('/api/device/commands').status_code==401
    assert c.get('/api/state').json['usage']==[]
    assert c.get('/api/state').json['lockers'][0]['student_id'] is None
    assert demo.post('/api/student/demo-release',json={},headers=h).status_code==200
    assert demo.get('/api/student/state').json['can_use_new'] is True
    real,rh,_=card_login(app,c,p)
    assert real.post('/api/student/demo-use',json={'locker_id':1},headers=rh).status_code==403

def test_duplicate_card_keeps_previous_binding(setup):
    app,c,p=setup;seed(p)
    p('/api/students',{'student_id':'20260002','name':'Other','phone':'13912345678'})
    assert p('/api/students/20260001/card',{'card_uid':'CARD-A001'}).status_code==200
    assert p('/api/students/20260002/card',{'card_uid':'CARD-A002'}).status_code==200
    assert p('/api/students/20260002/card',{'card_uid':'CARD-A001'}).status_code==409
    assert c.post('/api/device/login-qr',json={'card_uid':'CARD-A002'},headers=DEVICE).status_code==201
