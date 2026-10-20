import sqlite3
import pytest
from werkzeug.security import generate_password_hash
from app import create_app

PASSWORD = 'Test-Only-Pass-8493'

@pytest.fixture
def setup(tmp_path):
    app = create_app({'TESTING':True,'SECRET_KEY':'x'*40,'DATABASE':str(tmp_path/'test.db'),'SESSION_COOKIE_SECURE':False,'DEVICE_TOKEN':'device-test','INGEST_TOKEN':'ingest-test'})
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.execute('INSERT INTO admins(username,password) VALUES(?,?)', ('admin', generate_password_hash(PASSWORD)))
    conn.commit(); conn.close()
    client = app.test_client()
    client.get('/login')
    with client.session_transaction() as s: csrf=s['csrf']
    response=client.post('/login',data={'csrf':csrf,'username':'admin','password':PASSWORD})
    assert response.status_code==302
    with client.session_transaction() as s: csrf=s['csrf']
    def post(path,body): return client.post(path,json=body,headers={'X-CSRF-Token':csrf})
    return app,client,post

def seed(post):
    assert post('/api/students',{'student_id':'20260001','name':'测试学生','phone':'13800000000'}).status_code==200
    assert post('/api/lockers',{'label':'A-01'}).status_code==200

def command(post,action='reset'):
    return post('/api/lockers/1/command',{'action':action,'reason':'学生申请测试','confirm':'A-01','password':PASSWORD})

def test_auth_csrf_and_separate_tokens(setup):
    app,c,p=setup
    other=app.test_client()
    assert other.get('/api/state').status_code==401
    assert other.post('/api/lockers/1/command',json={}).status_code==401
    assert c.post('/api/lockers',json={'label':'X'}).status_code==403
    assert c.get('/api/device/commands',headers={'Authorization':'Bearer ingest-test'}).status_code==401
    assert other.get('/').status_code==200
    assert other.get('/admin').status_code==302
    assert c.get('/').status_code==200

def test_external_ingest_does_not_authorize(setup):
    _,c,p=setup
    r=c.post('/api/external/students',json={'student_id':'20260001','name':'外部','phone':'13800000000'},headers={'Authorization':'Bearer ingest-test'})
    assert r.status_code==200
    p('/api/lockers',{'label':'A-01'})
    assert p('/api/lockers/1/assign',{'student_id':'20260001'}).status_code==403
    assert c.get('/api/state').json['students'][0]['authorized']==0

def test_reset_waits_for_ack_and_idempotent(setup):
    _,c,p=setup;seed(p)
    assert p('/api/lockers/1/assign',{'student_id':'20260001'}).status_code==200
    r=command(p);assert r.status_code==202
    assert command(p).status_code==409
    assert c.get('/api/state').json['lockers'][0]['student_id']=='20260001'
    url='/api/device/commands/'+r.json['command_id']+'/ack'
    headers={'Authorization':'Bearer device-test'}
    assert c.post(url,json={'success':True},headers=headers).status_code==200
    assert c.post(url,json={'success':True},headers=headers).json['duplicate']
    state=c.get('/api/state').json
    assert state['lockers'][0]['student_id'] is None
    assert state['usage'][0]['ended']
    assert state['statistics'][0]['uses']==1

def test_failed_unlock_preserves_occupancy(setup):
    _,c,p=setup;seed(p);p('/api/lockers/1/assign',{'student_id':'20260001'})
    r=command(p,'unlock')
    assert c.post('/api/device/commands/'+r.json['command_id']+'/ack',json={'success':False},headers={'Authorization':'Bearer device-test'}).status_code==200
    assert c.get('/api/state').json['lockers'][0]['student_id']=='20260001'

def test_validation_and_csv(setup):
    _,c,p=setup
    assert p('/api/students',{'student_id':'bad'}).status_code==400
    seed(p)
    assert p('/api/lockers',{'label':'A-01'}).status_code==409
    p('/api/lockers/1/assign',{'student_id':'20260001'})
    assert c.get('/api/state?from=2099-01-01&to=2099-12-31').json['statistics'][0]['uses']==0
    assert c.get('/api/state?from=bad').status_code==400
    assert c.get('/api/export/statistics').data.startswith(b'\xef\xbb\xbf')
    p('/api/students',{'student_id':'20260002','name':'=1+1','phone':'13800000001'})
    assert "'=1+1" in c.get('/api/export/statistics').text

def test_card_store_release_idempotency(setup):
    _,c,p=setup;seed(p)
    h={'Authorization':'Bearer device-test'}
    body={'student_id':'20260001','locker_id':1,'request_id':'test-event-1'}
    r=c.post('/api/device/store',json=body,headers=h);assert r.status_code==202
    assert c.post('/api/device/store',json=body,headers=h).json['command_id']==r.json['command_id']
    assert c.get('/api/state').json['lockers'][0]['student_id'] is None
    ack='/api/device/commands/'+r.json['command_id']+'/ack'
    assert c.post(ack,json={'success':True},headers=h).status_code==200
    assert c.post(ack,json={'success':True},headers=h).json['duplicate']
    uid=c.get('/api/device/lockers/1',headers=h).json['usage_id']
    assert c.post('/api/device/release',json={'usage_id':uid},headers=h).status_code==200
    assert c.post('/api/device/release',json={'usage_id':uid},headers=h).json['duplicate']
    assert len(c.get('/api/state').json['usage'])==1

def test_expired_commands_cannot_change_state(setup):
    app,c,p=setup;seed(p);p('/api/lockers/1/assign',{'student_id':'20260001'})
    cid=command(p).json['command_id']
    conn=sqlite3.connect(app.config['DATABASE']);conn.execute("UPDATE commands SET expires='2000-01-01'");conn.commit();conn.close()
    assert c.post('/api/device/commands/'+cid+'/ack',json={'success':True},headers={'Authorization':'Bearer device-test'}).status_code==409
    assert c.get('/api/state').json['lockers'][0]['student_id']=='20260001'

def test_unique_assignment_and_control_confirmation(setup):
    _,c,p=setup;seed(p);p('/api/lockers',{'label':'A-02'})
    assert p('/api/lockers/1/assign',{'student_id':'20260001'}).status_code==200
    assert p('/api/lockers/2/assign',{'student_id':'20260001'}).status_code==409
    assert p('/api/lockers/1/command',{'action':'reset','reason':'test','confirm':'wrong','password':PASSWORD}).status_code==400
    assert p('/api/lockers/1/command',{'action':'reset','reason':'test','confirm':'A-01','password':'wrong'}).status_code==403

def test_login_rate_limit(setup):
    app,_,_=setup;c=app.test_client();c.get('/login')
    with c.session_transaction() as s: csrf=s['csrf']
    for _ in range(5):
        assert c.post('/login',data={'csrf':csrf,'username':'admin','password':'wrong'}).status_code==200
    assert c.post('/login',data={'csrf':csrf,'username':'admin','password':PASSWORD}).status_code==429
