"""Player registry + Twilio Verify. No public registration or payment claims."""
import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from urllib.error import HTTPError
from urllib.parse import urlencode,urlsplit
from urllib.request import Request,build_opener,HTTPSHandler,HTTPRedirectHandler

ROOT=Path(__file__).resolve().parent

class Problem(Exception):
    def __init__(self,status,message):self.status=status;self.message=message

def ident(value,limit=100):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,'+str(limit)+'}',value):raise Problem(400,'Некорректные данные')
    return value

def phone(value):
    if not isinstance(value,str) or not re.fullmatch(r'\+[1-9][0-9]{7,14}',value):raise Problem(400,'Телефон нужен в формате +кодстраныномер')
    return value

def digest(value):return hashlib.sha256(value.encode('utf-8')).hexdigest()

class Transaction:
    def __init__(self,connection,postgres):self.connection=connection;self.postgres=postgres
    def execute(self,sql,args=()):return self.connection.execute(sql.replace('?', '%s') if self.postgres else sql,args)
    def one(self,sql,args=()):
        cursor=self.execute(sql,args);row=cursor.fetchone()
        return None if row is None else dict(zip([c[0] for c in cursor.description],row))
    def session(self,sid):return self.one('SELECT * FROM sessions WHERE id=?'+(' FOR UPDATE' if self.postgres else ''),(sid,))
    def limit(self,bucket,period,maximum,now):
        row=self.one('INSERT INTO rate_buckets(bucket,slot,count) VALUES(?,?,1) ON CONFLICT(bucket,slot) DO UPDATE SET count=rate_buckets.count+1 RETURNING count',
                     (bucket,int(now)//period*period))
        if row['count']>maximum:raise Problem(429,'Слишком много попыток. Попробуйте позже.')

class Database:
    def __init__(self,url):self.url=url;self.postgres=url.startswith(('postgres://','postgresql://'))
    @contextmanager
    def transaction(self):
        if self.postgres:
            import psycopg
            connection=psycopg.connect(self.url,connect_timeout=5)
        else:
            connection=sqlite3.connect(self.url,timeout=5);connection.execute('BEGIN IMMEDIATE')
        try:
            yield Transaction(connection,self.postgres);connection.commit()
        except BaseException:
            connection.rollback();raise
        finally:connection.close()
    def initialize(self):
        with self.transaction() as tx:
            tx.execute('CREATE TABLE IF NOT EXISTS players(id TEXT PRIMARY KEY,phone TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1)')
            tx.execute('CREATE TABLE IF NOT EXISTS certificates(id TEXT PRIMARY KEY,player TEXT NOT NULL,product TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1)')
            tx.execute('CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,player TEXT NOT NULL,product TEXT NOT NULL,certificate TEXT NOT NULL,nonce TEXT NOT NULL,web_hash TEXT NOT NULL,poll_hash TEXT NOT NULL,state TEXT NOT NULL,expires BIGINT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,sends INTEGER NOT NULL DEFAULT 0,verification TEXT NOT NULL DEFAULT \'\')')
            tx.execute('CREATE TABLE IF NOT EXISTS rate_buckets(bucket TEXT NOT NULL,slot BIGINT NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(bucket,slot))')
    def grant(self,player,number,product,certificate):
        ident(player,32);phone(number);ident(product);ident(certificate,128)
        with self.transaction() as tx:
            existing=tx.one('SELECT phone FROM players WHERE id=?',(player,))
            if existing and existing['phone']!=number:raise ValueError('Player already has another phone; use an explicit administrative account recovery process')
            old=tx.one('SELECT player,product FROM certificates WHERE id=?',(certificate,))
            if old and (old['player']!=player or old['product']!=product):raise ValueError('Certificate already belongs to another player/product')
            tx.execute('INSERT INTO players(id,phone,active) VALUES(?,?,1) ON CONFLICT(id) DO UPDATE SET active=1',(player,number))
            tx.execute('INSERT INTO certificates(id,player,product,active) VALUES(?,?,?,1) ON CONFLICT(id) DO UPDATE SET active=1',(certificate,player,product))

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise Problem(502,'Ошибка SMS-провайдера')

class TwilioVerify:
    def __init__(self,account,secret,service):
        if not re.fullmatch(r'AC[0-9a-fA-F]{32}',account or '') or not re.fullmatch(r'VA[0-9a-fA-F]{32}',service or '') or not secret:
            raise RuntimeError('Set Twilio Account SID, Auth Token and Verify Service SID on the server')
        self.account=account;self.secret=secret;self.service=service
    def call(self,operation,data):
        authorization=base64.b64encode((self.account+':'+self.secret).encode()).decode()
        request=Request('https://verify.twilio.com/v2/Services/'+self.service+'/'+operation,
            data=urlencode(data).encode(),headers={'Authorization':'Basic '+authorization,'Content-Type':'application/x-www-form-urlencoded'})
        try:
            with build_opener(HTTPSHandler(),NoRedirect()).open(request,timeout=12) as response:raw=response.read(65537)
            if len(raw)>65536:raise ValueError()
            result=json.loads(raw)
            if not isinstance(result,dict):raise ValueError()
            return result
        except HTTPError as error:
            if operation=='VerificationCheck' and error.code in (400,404,429):raise Problem(400,'Код неверен или истёк срок проверки') from None
            raise Problem(502,'SMS-провайдер не принял запрос. Попробуйте позже.') from None
        except (OSError,ValueError):raise Problem(502,'SMS-провайдер недоступен') from None
    def send(self,number):
        result=self.call('Verifications',{'To':number,'Channel':'sms'})
        sid=result.get('sid','')
        if not re.fullmatch(r'VE[0-9a-fA-F]{32}',sid) or result.get('status')!='pending':raise Problem(502,'SMS-провайдер не начал проверку')
        return sid
    def check(self,verification,code,number):
        result=self.call('VerificationCheck',{'VerificationSid':verification,'Code':code})
        return result.get('status')=='approved' and result.get('to')==number and result.get('service_sid')==self.service

class IdentityService:
    def __init__(self,database,provider,public_url,*,enabled=False,now=time.time):
        parsed=urlsplit(public_url)
        if parsed.scheme!='https' or not parsed.netloc or parsed.path not in ('','/') or parsed.query or parsed.fragment or parsed.username:
            raise RuntimeError('PUBLIC_BASE_URL must be an HTTPS origin without path')
        self.db=database;self.provider=provider;self.public_url=public_url.rstrip('/');self.enabled=enabled;self.now=now
    def eligible(self,tx,player,product,certificate):
        row=tx.one('SELECT p.phone FROM players p JOIN certificates c ON c.player=p.id WHERE p.id=? AND c.product=? AND c.id=? AND p.active=1 AND c.active=1',(player,product,certificate))
        if row is None:raise Problem(403,'Игрок или сертификат не зарегистрирован. Обратитесь к автору игры.')
        return row['phone']
    def auth(self,tx,sid,token,kind):
        ident(sid,128)
        if not isinstance(token,str) or not 32<=len(token)<=128:raise Problem(403,'Нет доступа')
        session=tx.session(sid)
        if session is None or not hmac.compare_digest(session[kind+'_hash'],digest(token)):raise Problem(403,'Нет доступа')
        number=self.eligible(tx,session['player'],session['product'],session['certificate'])
        return session,number
    def create(self,data,remote):
        if not self.enabled or self.provider is None:raise Problem(503,'SMS-проверка ещё не подключена автором игры')
        player=ident(data.get('playerId'),32);product=ident(data.get('productId'));certificate=ident(data.get('certificateId'),128);nonce=ident(data.get('clientNonce'),128)
        now=int(self.now());sid=secrets.token_hex(16);web=secrets.token_urlsafe(32);poll=secrets.token_urlsafe(32)
        with self.db.transaction() as tx:
            tx.limit('sessions:'+digest(remote),600,40,now)
            tx.limit('sessions-global',3600,300,now)
        with self.db.transaction() as tx:
            self.eligible(tx,player,product,certificate)
            tx.limit('player-sessions:'+player,600,10,now)
            tx.execute('DELETE FROM sessions WHERE expires<?',(now-86400,))
            tx.execute('DELETE FROM rate_buckets WHERE slot<?',(now-172800,))
            tx.execute('INSERT INTO sessions(id,player,product,certificate,nonce,web_hash,poll_hash,state,expires) VALUES(?,?,?,?,?,?,?,?,?)',
                       (sid,player,product,certificate,nonce,digest(web),digest(poll),'created',now+600))
        return {'id':sid,'pollToken':poll,'verificationUrl':self.public_url+'/verify#'+sid+'.'+web,
                'playerId':player,'productId':product,'certificateId':certificate,'clientNonce':nonce}
    def status(self,sid,token):
        with self.db.transaction() as tx:
            s,_=self.auth(tx,sid,token,'poll')
            state='expired' if s['expires']<=self.now() else 'verified' if s['state']=='verified' else 'pending'
            return {'id':s['id'],'status':state,'playerId':s['player'],'productId':s['product'],
                    'certificateId':s['certificate'],'clientNonce':s['nonce'],'expiresAt':s['expires']}
    def send(self,sid,token,data):
        if not self.enabled:raise Problem(503,'SMS отключены')
        number=phone(data.get('phone'));now=int(self.now())
        with self.db.transaction() as tx:
            attempt,_=self.auth(tx,sid,token,'web')
            tx.limit('phone-input:'+attempt['player'],600,8,now)
        with self.db.transaction() as tx:
            s,registered=self.auth(tx,sid,token,'web')
            if s['expires']<=now or s['state']=='verified':raise Problem(400,'Начните новую проверку из игры')
            if s['state'] in ('sending','checking'):raise Problem(409,'Запрос уже выполняется')
            if s['sends']>=3:raise Problem(429,'Достигнут предел отправок. Начните проверку позже.')
            if not hmac.compare_digest(number,registered):raise Problem(403,'Телефон не совпадает с записью игрока')
            tx.limit('sms-minute:'+s['player'],60,1,now)
            tx.limit('sms-day:'+s['player'],86400,5,now)
            tx.limit('sms-global',86400,100,now)
            tx.execute('UPDATE sessions SET state=?,sends=sends+1 WHERE id=?',('sending',sid))
        try:verification=self.provider.send(registered)
        except Exception:
            with self.db.transaction() as tx:tx.execute('UPDATE sessions SET state=? WHERE id=? AND state=?',('created',sid,'sending'))
            raise
        with self.db.transaction() as tx:tx.execute('UPDATE sessions SET state=?,verification=? WHERE id=? AND state=?',('pending',verification,sid,'sending'))
        return {'status':'sent'}
    def check(self,sid,token,data):
        code=data.get('code')
        if not isinstance(code,str) or not re.fullmatch(r'[0-9]{4,10}',code):raise Problem(400,'Введите код из SMS')
        with self.db.transaction() as tx:
            s,number=self.auth(tx,sid,token,'web')
            if s['expires']<=self.now() or s['state']!='pending' or not s['verification']:raise Problem(400,'Сначала запросите SMS или начните новую проверку')
            if s['attempts']>=5:raise Problem(429,'Слишком много неверных кодов')
            tx.execute('UPDATE sessions SET state=?,attempts=attempts+1 WHERE id=?',('checking',sid))
        try:approved=self.provider.check(s['verification'],code,number)
        except Exception:
            with self.db.transaction() as tx:tx.execute('UPDATE sessions SET state=? WHERE id=? AND state=?',('pending',sid,'checking'))
            raise
        with self.db.transaction() as tx:
            # Re-check ownership/revocation after the network call.
            self.eligible(tx,s['player'],s['product'],s['certificate'])
            if s['expires']<=self.now():raise Problem(400,'Срок проверки истёк. Начните заново из игры.')
            tx.execute('UPDATE sessions SET state=?,expires=? WHERE id=? AND state=?',
                       ('verified' if approved else 'pending',int(self.now())+43200 if approved else s['expires'],sid,'checking'))
        if not approved:raise Problem(400,'Код неверен')
        return {'status':'verified'}

class Application:
    def __init__(self,service):self.service=service
    def __call__(self,environ,start_response):
        try:
            path=environ.get('PATH_INFO','/');method=environ.get('REQUEST_METHOD','GET')
            headers=[('Cache-Control','no-store'),('X-Content-Type-Options','nosniff'),('Referrer-Policy','no-referrer'),
                     ('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")]
            if method=='GET' and path in ('/','/verify','/verify.js','/verify.css'):
                file={'/':'index.html','/verify':'index.html','/verify.js':'verify.js','/verify.css':'verify.css'}[path]
                kind='text/html' if file.endswith('.html') else 'text/javascript' if file.endswith('.js') else 'text/css'
                raw=(ROOT/'static'/file).read_bytes();headers.append(('Content-Type',kind+'; charset=utf-8'));status=200
            else:
                authorization=environ.get('HTTP_AUTHORIZATION','');token=authorization[7:] if authorization.startswith('Bearer ') else ''
                data={}
                if method=='POST':
                    if environ.get('CONTENT_TYPE','').split(';')[0]!='application/json':raise Problem(415,'Нужен JSON')
                    length=int(environ.get('CONTENT_LENGTH') or 0)
                    if not 0<length<=4096:raise Problem(413,'Слишком большой запрос')
                    data=json.loads(environ['wsgi.input'].read(length))
                    if not isinstance(data,dict):raise Problem(400,'Нужен объект JSON')
                match=re.fullmatch(r'/api/sessions/([A-Za-z0-9_-]{1,128})(?:/(phone|code))?',path)
                if method=='GET' and path=='/health':result={'status':'ok','smsEnabled':self.service.enabled}
                elif method=='POST' and path=='/api/sessions':result=self.service.create(data,environ.get('REMOTE_ADDR','unknown'))
                elif match:
                    sid,action=match.groups()
                    if method=='GET' and action is None:result=self.service.status(sid,token)
                    elif method=='POST' and action=='phone':result=self.service.send(sid,token,data)
                    elif method=='POST' and action=='code':result=self.service.check(sid,token,data)
                    else:raise Problem(405,'Метод не поддерживается')
                else:raise Problem(404,'Не найдено')
                raw=json.dumps(result,ensure_ascii=False).encode();headers.append(('Content-Type','application/json; charset=utf-8'));status=200
        except Problem as error:status=error.status;raw=json.dumps({'error':error.message},ensure_ascii=False).encode();headers=[('Content-Type','application/json; charset=utf-8'),('Cache-Control','no-store')]
        except (ValueError,UnicodeError,KeyError):status=400;raw=b'{"error":"Invalid request"}';headers=[('Content-Type','application/json'),('Cache-Control','no-store')]
        except Exception:status=503;raw=b'{"error":"Service temporarily unavailable"}';headers=[('Content-Type','application/json'),('Cache-Control','no-store')]
        headers.append(('Content-Length',str(len(raw))));start_response(str(status)+' '+{200:'OK',400:'Bad Request',403:'Forbidden',404:'Not Found',405:'Method Not Allowed',409:'Conflict',413:'Payload Too Large',415:'Unsupported Media Type',429:'Too Many Requests',502:'Bad Gateway',503:'Service Unavailable'}.get(status,'Error'),headers)
        return [raw]

def from_environment():
    url=os.environ.get('DATABASE_URL','')
    if not url.startswith(('postgres://','postgresql://')):raise RuntimeError('DATABASE_URL must use persistent PostgreSQL')
    database=Database(url);database.initialize()
    enabled=os.environ.get('SMS_ENABLED','false').lower()=='true'
    provider=TwilioVerify(os.environ.get('TWILIO_ACCOUNT_SID'),os.environ.get('TWILIO_AUTH_TOKEN'),os.environ.get('TWILIO_VERIFY_SERVICE_SID')) if enabled else None
    return Application(IdentityService(database,provider,os.environ['PUBLIC_BASE_URL'],enabled=enabled))
