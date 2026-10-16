"""Opt-in player registration; never treats a client certificate as payment proof."""
from datetime import datetime, timezone
import hmac
import json
import os
import re
import secrets
from urllib.request import Request, build_opener, HTTPSHandler
from identity_server import Problem, PhoneGateway, NoRedirect, ident, phone, digest, password_matches


def email(value, optional=False):
    if optional and not value:return ''
    if not isinstance(value,str) or len(value)>254 or not re.fullmatch(r'[A-Za-z0-9.!#$%&\'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}',value):
        raise Problem(400,'Укажите корректный email')
    return value


def certificate_fields(value, now):
    if not isinstance(value,dict) or value.get('schema')!='myengine-license/v1' or value.get('licenseStatus')!='issued':
        raise Problem(400,'Выберите выданный JSON-сертификат MyEngine')
    if value.get('signature') is not None:raise Problem(400,'Для подписанного сертификата требуется отдельный проверяющий модуль')
    if value.get('grantType') not in ('developer','purchase','manual'):raise Problem(400,'Неизвестный тип сертификата')
    try:
        def date(text):
            if not isinstance(text,str) or len(text)>64:raise ValueError()
            result=datetime.fromisoformat(text.replace('Z','+00:00'))
            if result.tzinfo is None:raise ValueError()
            return result.timestamp()
        issued=date(value.get('issuedAt'));expiry=date(value['expiresAt']) if value.get('expiresAt') else None
        if issued>now+300 or (expiry is not None and (expiry<=now or expiry<=issued)):raise ValueError()
    except (ValueError,TypeError,OverflowError):raise Problem(400,'Сертификат просрочен или содержит некорректную дату') from None
    return ident(value.get('playerId'),32),ident(value.get('productId')),ident(value.get('certificateId'),128),expiry


def grant(tx, player, number, product, certificate, *, reactivate=False):
    # Conditions are part of the writes, so concurrent requests cannot steal an ID.
    active='' if reactivate else ' AND players.active=1'
    row=tx.one('INSERT INTO players(id,phone,active) VALUES(?,?,1) ON CONFLICT(id) DO UPDATE SET active=1 WHERE players.phone=EXCLUDED.phone'+active+' RETURNING id',(player,number))
    if row is None:raise Problem(409,'Игрок заблокирован или привязан к другому телефону. Обратитесь к автору.')
    active='' if reactivate else ' AND certificates.active=1'
    row=tx.one('INSERT INTO certificates(id,player,product,active) VALUES(?,?,?,1) ON CONFLICT(id) DO UPDATE SET active=1 WHERE certificates.player=EXCLUDED.player AND certificates.product=EXCLUDED.product'+active+' RETURNING id',(certificate,player,product))
    if row is None:raise Problem(409,'Сертификат заблокирован или уже привязан к другому игроку / товару.')


class EmailSender:
    def __init__(self,key='',sender=''):self.key=key;self.sender=sender
    @property
    def configured(self):
        try:email(self.sender);return bool(self.key)
        except Problem:return False
    def send(self,rid,payload):
        if not self.configured:return 'not_configured'
        request=Request('https://api.resend.com/emails',data=payload.encode(),headers={
            'Authorization':'Bearer '+self.key,'Content-Type':'application/json','Idempotency-Key':'myengine-registration-'+rid})
        try:
            with build_opener(HTTPSHandler(),NoRedirect()).open(request,timeout=12) as response:
                result=json.loads(response.read(65536))
            return 'accepted' if result.get('id') else 'failed'
        except Exception:return 'failed'


class Registration:
    def __init__(self,service,mailer=None):
        self.service=service;self.db=service.db;self.now=service.now
        self.mailer=mailer or EmailSender(os.environ.get('RESEND_API_KEY',''),os.environ.get('EMAIL_FROM',''))
        with self.db.transaction() as tx:
            tx.execute("CREATE TABLE IF NOT EXISTS registration_settings(id INTEGER PRIMARY KEY,mode TEXT NOT NULL,products TEXT NOT NULL,notify INTEGER NOT NULL,recipient TEXT NOT NULL)")
            tx.execute("INSERT INTO registration_settings VALUES(1,'closed','[]',0,'') ON CONFLICT(id) DO NOTHING")
            tx.execute("CREATE TABLE IF NOT EXISTS owner_sessions(token_hash TEXT PRIMARY KEY,expires BIGINT NOT NULL)")
            tx.execute("CREATE TABLE IF NOT EXISTS registration_requests(id TEXT PRIMARY KEY,player TEXT NOT NULL,product TEXT NOT NULL,certificate TEXT NOT NULL,phone TEXT NOT NULL,email TEXT NOT NULL,note TEXT NOT NULL,state TEXT NOT NULL,created BIGINT NOT NULL,expires BIGINT NOT NULL,certificate_expiry BIGINT,web_hash TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,verification TEXT NOT NULL DEFAULT '',mail_status TEXT NOT NULL DEFAULT 'off',mail_payload TEXT NOT NULL DEFAULT '')")
            tx.execute('CREATE INDEX IF NOT EXISTS registration_pending ON registration_requests(state,created)')
    def settings(self,tx=None):
        if tx is None:
            with self.db.transaction() as tx:return self.settings(tx)
        r=tx.one('SELECT * FROM registration_settings WHERE id=1')
        return {'mode':r['mode'],'products':json.loads(r['products']),'notify':bool(r['notify']),'recipient':r['recipient']}
    def public_config(self):
        s=self.settings()
        return {'mode':s['mode'],'products':s['products'] if s['mode']=='automatic' else [],'smsEnabled':self.service.enabled}
    def limit(self,bucket,period,maximum):
        with self.db.transaction() as tx:tx.limit(bucket,period,maximum,int(self.now()))
    def login(self,data,remote):
        self.limit('admin-ip:'+digest(remote),900,10)
        self.limit('admin-global',900,30)
        owner=self.service.owner
        if not owner or data.get('phone')!=owner['phone'] or not password_matches(data.get('password'),owner['hash']):
            raise Problem(403,'Неверный номер или пароль владельца')
        token=secrets.token_urlsafe(32);now=int(self.now())
        with self.db.transaction() as tx:
            tx.execute('DELETE FROM owner_sessions WHERE expires<=?',(now,))
            tx.execute('INSERT INTO owner_sessions VALUES(?,?)',(digest(token),now+3600))
        return {'token':token,'expiresAt':now+3600}
    def authorize(self,tx,token):
        if not isinstance(token,str) or not 32<=len(token)<=128:raise Problem(403,'Войдите владельцем')
        if not tx.one('SELECT token_hash FROM owner_sessions WHERE token_hash=? AND expires>?',(digest(token),int(self.now()))):raise Problem(403,'Войдите владельцем заново')
    def save_settings(self,token,data):
        mode=data.get('mode');products=data.get('products',[]);notify=data.get('notify',False)
        if mode not in ('closed','automatic','approval') or not isinstance(products,list) or len(products)>50 or not isinstance(notify,bool):raise Problem(400,'Некорректные настройки')
        products=list(dict.fromkeys(ident(p) for p in products))
        recipient=email(data.get('recipient',''),optional=not notify)
        if mode=='automatic' and not products:raise Problem(400,'Укажите товары, доступ к которым разрешено выдавать бесплатно')
        if mode=='automatic' and (not self.service.enabled or self.service.provider is None):raise Problem(400,'Для свободной регистрации сначала включите SMS-проверку на сервере')
        with self.db.transaction() as tx:
            self.authorize(tx,token)
            tx.execute('UPDATE registration_settings SET mode=?,products=?,notify=?,recipient=? WHERE id=1',(mode,json.dumps(products),int(notify),recipient))
        return {'status':'saved','mailConfigured':self.mailer.configured}
    def conflicts(self,tx,player,product,cert,number):
        owner=self.service.owner
        if owner and (player==owner['player'] or number==owner['phone']):raise Problem(403,'Для владельца используйте вход по паролю')
        p=tx.one('SELECT * FROM players WHERE id=?',(player,))
        c=tx.one('SELECT * FROM certificates WHERE id=?',(cert,))
        if p and (p['phone']!=number or not p['active']):raise Problem(409,'Этот игрок уже привязан к другому номеру или заблокирован')
        if c and (c['player']!=player or c['product']!=product or not c['active']):raise Problem(409,'Этот сертификат уже занят или заблокирован')
        if p and c:raise Problem(409,'Игрок и сертификат уже зарегистрированы. Вернитесь в игру и начните вход.')
    def submit(self,data,remote):
        self.limit('register-ip:'+digest(remote),3600,10)
        self.limit('register-global',86400,300)
        now=int(self.now());player,product,cert,expiry=certificate_fields(data.get('certificate'),now)
        number=phone(data.get('phone'));contact=email(data.get('email',''),optional=True);note=data.get('note','')
        if not isinstance(note,str) or len(note)>500:raise Problem(400,'Комментарий: не более 500 символов')
        self.limit('register-phone:'+digest(number),86400,5)
        rid=secrets.token_hex(16);token=secrets.token_urlsafe(32)
        with self.db.transaction() as tx:
            s=self.settings(tx)
            if s['mode']=='closed':raise Problem(403,'Автор пока не открыл регистрацию')
            self.conflicts(tx,player,product,cert,number)
            if tx.one("SELECT id FROM registration_requests WHERE certificate=? AND state IN ('pending','unverified','sending','checking') AND expires>?",(cert,now)):
                raise Problem(409,'Заявка для этого сертификата уже отправлена. Дождитесь решения или завершите проверку в открытой вкладке.')
            automatic=s['mode']=='automatic'
            if automatic and product not in s['products']:raise Problem(403,'Этот товар не доступен для свободной регистрации. Обратитесь к автору.')
            if automatic and (not self.service.enabled or self.service.provider is None):raise Problem(503,'SMS-проверка сейчас отключена')
            state='unverified' if automatic else 'pending';end=now+(600 if automatic else 604800)
            if expiry is not None:end=min(end,int(expiry))
            verification='';mail_status='off';payload=''
            if automatic:
                tx.limit('sms-global',86400,100,now)
                tx.limit('registration-sms-minute:'+digest(number),60,1,now)
                if isinstance(self.service.provider,PhoneGateway):
                    verification=self.service.provider.enqueue(tx,{'id':'R-'+rid,'expires':end},number,now)
                else:state='sending'
            elif s['notify']:
                mail_status='waiting'
                payload=json.dumps({'from':self.mailer.sender,'to':[s['recipient']],
                    'subject':'MyEngine: заявка на регистрацию '+rid[:8],
                    'text':'Игрок хочет зарегистрироваться.\nЗаявка: '+rid+'\nИгрок: '+player+'\nТовар: '+product+'\nСертификат: '+cert+'\nТелефон (не подтверждён): '+number+'\nEmail: '+contact+'\nКомментарий: '+note+'\n\nРешение: '+self.service.public_url+'/moderation\nЗаявка не подтверждает оплату.'},ensure_ascii=False)
            tx.execute('INSERT INTO registration_requests(id,player,product,certificate,phone,email,note,state,created,expires,certificate_expiry,web_hash,verification,mail_status,mail_payload) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (rid,player,product,cert,number,contact,note,state,now,end,expiry,digest(token),verification,mail_status,payload))
        if state=='sending':
            try:
                verification=self.service.provider.send(number)
                with self.db.transaction() as tx:tx.execute("UPDATE registration_requests SET state='unverified',verification=? WHERE id=? AND state='sending'",(verification,rid))
            except Exception:
                with self.db.transaction() as tx:tx.execute("UPDATE registration_requests SET state='failed' WHERE id=? AND state='sending'",(rid,))
                raise
        if mail_status=='waiting':mail_status=self.notify(rid)
        return {'id':rid,'token':token,'status':'code_required' if automatic else 'pending','mailStatus':mail_status}
    def request(self,tx,rid,token):
        ident(rid,32)
        r=tx.one('SELECT * FROM registration_requests WHERE id=?'+(' FOR UPDATE' if tx.postgres else ''),(rid,))
        if not r or not isinstance(token,str) or not 32<=len(token)<=128 or not hmac.compare_digest(r['web_hash'],digest(token)):raise Problem(403,'Нет доступа к заявке')
        return r
    def status(self,rid,token):
        with self.db.transaction() as tx:
            r=self.request(tx,rid,token)
            return {'status':'expired' if r['state'] not in ('approved','rejected') and r['expires']<=self.now() else r['state']}
    def check(self,rid,token,data):
        code=data.get('code')
        if not isinstance(code,str) or not re.fullmatch(r'[0-9]{4,10}',code):raise Problem(400,'Введите код из SMS')
        with self.db.transaction() as tx:
            r=self.request(tx,rid,token)
            if r['state']!='unverified' or r['expires']<=self.now():raise Problem(400,'Проверка недоступна или истекла. Начните регистрацию заново.')
            if r['attempts']>=5:raise Problem(429,'Слишком много неверных кодов')
            if not self.service.enabled or self.service.provider is None:raise Problem(503,'SMS-проверка отключена')
            tx.execute("UPDATE registration_requests SET state='checking',attempts=attempts+1 WHERE id=?",(rid,))
        try:approved=self.service.provider.check(r['verification'],code,r['phone'])
        except Exception:
            with self.db.transaction() as tx:tx.execute("UPDATE registration_requests SET state='unverified' WHERE id=? AND state='checking'",(rid,))
            raise
        try:
            with self.db.transaction() as tx:
                r=self.request(tx,rid,token);s=self.settings(tx)
                if r['state']!='checking' or r['expires']<=self.now():raise Problem(400,'Срок проверки истёк')
                if s['mode']!='automatic' or r['product'] not in s['products']:raise Problem(403,'Автор изменил правила регистрации. Обратитесь к автору.')
                if approved:
                    self.conflicts(tx,r['player'],r['product'],r['certificate'],r['phone'])
                    grant(tx,r['player'],r['phone'],r['product'],r['certificate'])
                tx.execute('UPDATE registration_requests SET state=? WHERE id=?',('approved' if approved else 'unverified',rid))
        except Problem:
            with self.db.transaction() as tx:tx.execute("UPDATE registration_requests SET state='failed' WHERE id=? AND state='checking'",(rid,))
            raise
        if not approved:raise Problem(400,'Код неверен')
        return {'status':'approved'}
    def notify(self,rid):
        with self.db.transaction() as tx:
            r=tx.one('SELECT * FROM registration_requests WHERE id=?'+(' FOR UPDATE' if tx.postgres else ''),(rid,))
            if not r or r['mail_status'] not in ('waiting','failed','not_configured'):return r['mail_status'] if r else 'off'
            # Resend deduplicates for 24 hours. Never retry beyond that window.
            if r['created']<self.now()-82800:return 'retry_expired'
            tx.execute("UPDATE registration_requests SET mail_status='sending' WHERE id=?",(rid,))
            payload=r['mail_payload']
            if r['mail_status']=='not_configured' or not json.loads(payload).get('from'):
                value=json.loads(payload);value['from']=self.mailer.sender;payload=json.dumps(value,ensure_ascii=False)
                tx.execute('UPDATE registration_requests SET mail_payload=? WHERE id=?',(payload,rid))
        result=self.mailer.send(rid,payload)
        with self.db.transaction() as tx:tx.execute('UPDATE registration_requests SET mail_status=? WHERE id=?',(result,rid))
        return result
    def overview(self,token):
        with self.db.transaction() as tx:
            self.authorize(tx,token);s=self.settings(tx)
            cursor=tx.execute("SELECT id,player,product,certificate,phone,email,note,state,created,expires,mail_status FROM registration_requests WHERE state='pending' AND expires>? ORDER BY created LIMIT 100",(int(self.now()),))
            names=[c[0] for c in cursor.description];requests=[dict(zip(names,row)) for row in cursor.fetchall()]
        return {'settings':s,'requests':requests,'mailConfigured':self.mailer.configured}
    def decide(self,token,rid,action):
        ident(rid,32)
        with self.db.transaction() as tx:
            self.authorize(tx,token)
            r=tx.one('SELECT * FROM registration_requests WHERE id=?'+(' FOR UPDATE' if tx.postgres else ''),(rid,))
            if not r:raise Problem(404,'Заявка не найдена')
            if action=='retry-mail':pass
            elif action in ('approve','reject'):
                target='approved' if action=='approve' else 'rejected'
                if r['state']==target:return {'status':target}
                if r['state']!='pending' or r['expires']<=self.now():raise Problem(409,'Заявка уже обработана или истекла')
                if action=='approve':
                    self.conflicts(tx,r['player'],r['product'],r['certificate'],r['phone'])
                    grant(tx,r['player'],r['phone'],r['product'],r['certificate'])
                tx.execute('UPDATE registration_requests SET state=? WHERE id=?',(target,rid))
            else:raise Problem(404,'Не найдено')
        return {'mailStatus':self.notify(rid)} if action=='retry-mail' else {'status':target}
    def route(self,method,path,token,data,remote):
        if method=='GET' and path=='/api/registration/config':return self.public_config()
        if method=='POST' and path=='/api/registrations':return self.submit(data,remote)
        if method=='POST' and path=='/api/moderation/login':return self.login(data,remote)
        if method=='GET' and path=='/api/moderation':return self.overview(token)
        if method=='POST' and path=='/api/moderation/settings':return self.save_settings(token,data)
        if method=='POST' and path=='/api/moderation/logout':
            with self.db.transaction() as tx:
                self.authorize(tx,token);tx.execute('DELETE FROM owner_sessions WHERE token_hash=?',(digest(token),))
            return {'status':'ok'}
        match=re.fullmatch(r'/api/registrations/([a-f0-9]{32})(/code)?',path)
        if match:
            if method=='GET' and not match[2]:return self.status(match[1],token)
            if method=='POST' and match[2]:return self.check(match[1],token,data)
        match=re.fullmatch(r'/api/moderation/([a-f0-9]{32})/(approve|reject|retry-mail)',path)
        if method=='POST' and match:return self.decide(token,match[1],match[2])
        raise Problem(404,'Не найдено')
