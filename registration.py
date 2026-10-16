"""Opt-in player registration; never treats a client certificate as payment proof."""
from datetime import datetime
import hmac
import json
import re
import secrets
from urllib.parse import quote
from identity_server import Problem, PhoneGateway, ident, phone, digest, password_matches
from security_audit import Security,clean


DEFAULT_CONTACT='alekandrza14@gmail.com'

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
    if value.get('grantType')=='developer':raise Problem(403,'Сертификат разработчика нельзя зарегистрировать как обычный игрок.',{'code':'developer_claim_forbidden'})
    return ident(value.get('playerId'),32),ident(value.get('productId')),ident(value.get('certificateId'),128),expiry


def grant(tx, player, number, product, certificate, *, reactivate=False):
    # Conditions are part of the writes, so concurrent requests cannot steal an ID.
    active='' if reactivate else ' AND players.active=1'
    row=tx.one('INSERT INTO players(id,phone,active) VALUES(?,?,1) ON CONFLICT(id) DO UPDATE SET active=1 WHERE players.phone=EXCLUDED.phone'+active+' RETURNING id',(player,number))
    if row is None:raise Problem(409,'Игрок заблокирован или привязан к другому телефону. Обратитесь к автору.')
    active='' if reactivate else ' AND certificates.active=1'
    row=tx.one('INSERT INTO certificates(id,player,product,active) VALUES(?,?,?,1) ON CONFLICT(id) DO UPDATE SET active=1 WHERE certificates.player=EXCLUDED.player AND certificates.product=EXCLUDED.product'+active+' RETURNING id',(certificate,player,product))
    if row is None:raise Problem(409,'Сертификат заблокирован или уже привязан к другому игроку / товару.')


class Registration:
    def __init__(self,service):
        self.service=service;self.db=service.db;self.now=service.now
        if self.service.security is None:self.service.security=Security(service)
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
        return {'mode':r['mode'],'products':json.loads(r['products']),'recipient':r['recipient'] or DEFAULT_CONTACT}
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
        if not isinstance(token,str) or not 32<=len(token)<=128:raise Problem(403,'Войдите владельцем',{'code':'owner_session_required'})
        if not tx.one('SELECT token_hash FROM owner_sessions WHERE token_hash=? AND expires>?',(digest(token),int(self.now()))):raise Problem(403,'Войдите владельцем заново',{'code':'owner_session_required'})
    def save_settings(self,token,data):
        mode=data.get('mode');products=data.get('products',[])
        if mode not in ('closed','automatic','approval') or not isinstance(products,list) or len(products)>50:raise Problem(400,'Некорректные настройки')
        products=list(dict.fromkeys(ident(p) for p in products))
        recipient=email(data.get('recipient') or DEFAULT_CONTACT)
        if mode=='automatic' and not products:raise Problem(400,'Укажите товары, доступ к которым разрешено выдавать бесплатно')
        if mode=='automatic' and (not self.service.enabled or self.service.provider is None):raise Problem(400,'Для свободной регистрации сначала включите SMS-проверку на сервере')
        with self.db.transaction() as tx:
            self.authorize(tx,token)
            tx.execute('UPDATE registration_settings SET mode=?,products=?,notify=?,recipient=? WHERE id=1',(mode,json.dumps(products),0,recipient))
        return {'status':'saved'}
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
            # Keep legacy columns for compatible, non-destructive upgrades.
            verification='';mail_status='off';payload=''
            if automatic:
                tx.limit('sms-global',86400,100,now)
                tx.limit('registration-sms-minute:'+digest(number),60,1,now)
                if isinstance(self.service.provider,PhoneGateway):
                    verification=self.service.provider.enqueue(tx,{'id':'R-'+rid,'expires':end},number,now)
                else:state='sending'
            tx.execute('INSERT INTO registration_requests(id,player,product,certificate,phone,email,note,state,created,expires,certificate_expiry,web_hash,verification,mail_status,mail_payload) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (rid,player,product,cert,number,contact,note,state,now,end,expiry,digest(token),verification,mail_status,payload))
            self.service.security.claim(tx,rid,data['certificate'],data)
        if state=='sending':
            try:
                verification=self.service.provider.send(number)
                with self.db.transaction() as tx:tx.execute("UPDATE registration_requests SET state='unverified',verification=? WHERE id=? AND state='sending'",(verification,rid))
            except Exception:
                with self.db.transaction() as tx:tx.execute("UPDATE registration_requests SET state='failed' WHERE id=? AND state='sending'",(rid,))
                raise
        result={'id':rid,'token':token,'status':'code_required' if automatic else 'pending'}
        if not automatic:
            with self.db.transaction() as tx:
                result['emailDraft']=self.email_draft(tx.one('SELECT * FROM registration_requests WHERE id=?',(rid,)),s['recipient'])
        return result
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
    def email_draft(self,r,recipient):
        recipient=email(recipient)
        subject='#verify — регистрация игрока '+r['player']
        body='\r\n'.join([
            'Здравствуйте! Хочу зарегистрироваться в игре.',
            'Заявка: '+r['id'],'ID игрока: '+r['player'],'Товар: '+r['product'],
            'Сертификат: '+r['certificate'],'Телефон для входа: '+r['phone'],
            'Email для ответа: '+(r['email'] or '[адрес, с которого отправляю письмо]'),
            '', 'Игровой ник: [укажи ник]',
            'Страница Steam — по желанию: [ссылка]',
            'Купленные игры, которые хочу указать — по желанию: [список]',
            'Основание для доступа / номер заказа: [укажи, если требуется]',
            'Почему хочу зарегистрироваться: '+(r['note'] or '[напиши кратко]'),
            '', 'Кабинет автора для рассмотрения: '+self.service.public_url+'/moderation',
            'Открытие и отправка письма сами по себе не выдают доступ.'
        ])
        return {'to':recipient,'subject':subject,'body':body,
            'href':'mailto:'+quote(recipient,safe='@')+'?subject='+quote(subject,safe='')+'&body='+quote(body,safe='')}
    def overview(self,token):
        with self.db.transaction() as tx:
            self.authorize(tx,token);s=self.settings(tx)
            cursor=tx.execute("SELECT id,player,product,certificate,phone,email,note,state,created,expires,mail_status FROM registration_requests WHERE state='pending' AND expires>? ORDER BY created LIMIT 100",(int(self.now()),))
            names=[c[0] for c in cursor.description];requests=[dict(zip(names,row)) for row in cursor.fetchall()]
            for r in requests:
                r['claims']=tx.one('SELECT grant_type,payment_status,payment_availability,decision_reason,decision_reference FROM registration_claims WHERE request_id=?',(r['id'],)) or {'grant_type':'unknown','payment_status':'unknown','payment_availability':'unknown'}
                r['paymentVerified']=False
                r['certificateRole']='player_request'
                r['flags']=['payment_not_verified']
                if r['claims']['payment_availability']=='unavailable':r['flags'].append('payment_unavailable_reported')
                if r['claims']['grant_type']=='developer':r['flags'].append('developer_claim_blocked')
        return {'settings':s,'requests':requests}
    def decide(self,token,rid,action,data=None):
        data=data or {}
        ident(rid,32)
        with self.db.transaction() as tx:
            self.authorize(tx,token)
            r=tx.one('SELECT * FROM registration_requests WHERE id=?'+(' FOR UPDATE' if tx.postgres else ''),(rid,))
            if not r:raise Problem(404,'Заявка не найдена')
            if action in ('approve','reject'):
                target='approved' if action=='approve' else 'rejected'
                if r['state']==target:return {'status':target}
                if r['state']!='pending' or r['expires']<=self.now():raise Problem(409,'Заявка уже обработана или истекла')
                if action=='approve':
                    claims=tx.one('SELECT grant_type FROM registration_claims WHERE request_id=?',(rid,))
                    if claims and claims['grant_type']=='developer':raise Problem(403,'Сертификат разработчика нельзя одобрить обычному игроку')
                    reason=data.get('accessReason','manual_access')
                    if reason not in ('manual_access','free_grant','purchase_reviewed'):raise Problem(400,'Выберите основание доступа')
                    reference=clean(data.get('paymentReference',''),120)
                    if reason=='purchase_reviewed' and not reference:raise Problem(400,'Укажите номер операции, которую проверили лично')
                    tx.execute('UPDATE registration_claims SET decision_reason=?,decision_reference=? WHERE request_id=?',(reason,reference,rid))
                    self.conflicts(tx,r['player'],r['product'],r['certificate'],r['phone'])
                    grant(tx,r['player'],r['phone'],r['product'],r['certificate'])
                tx.execute('UPDATE registration_requests SET state=? WHERE id=?',(target,rid))
            else:raise Problem(404,'Не найдено')
        return {'status':target}
    def route(self,method,path,token,data,remote):
        if method=='GET' and path=='/api/registration/config':return self.public_config()
        if method=='POST' and path=='/api/registrations':return self.submit(data,remote)
        if method=='POST' and path=='/api/moderation/login':return self.login(data,remote)
        if path=='/api/moderation/security' and method in ('GET','POST'):
            before=data.get('before')
            if before is not None:
                if not isinstance(before,dict) or type(before.get('created')) is not int or not re.fullmatch(r'[a-f0-9]{32}',str(before.get('id',''))):raise Problem(400,'Некорректная страница журнала')
                before=(before['created'],before['id'])
            return self.service.security.overview(token,before)
        if method=='POST' and path=='/api/moderation/developer-certificate':return self.service.security.replace_binding(token,data)
        if method=='POST' and path=='/api/moderation/logout-others':
            with self.db.transaction() as tx:
                self.authorize(tx,token);tx.execute('DELETE FROM owner_sessions WHERE token_hash<>?',(digest(token),))
            return {'status':'ok'}
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
        match=re.fullmatch(r'/api/moderation/([a-f0-9]{32})/(approve|reject)',path)
        if method=='POST' and match:return self.decide(token,match[1],match[2],data)
        raise Problem(404,'Не найдено')
