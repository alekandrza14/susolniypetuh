"""Owner-only security journal. Client metadata is a signal, never identity proof."""
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from identity_server import Problem, digest, ident, password_matches


def clean(value,limit=160):
    if not isinstance(value,str):return ''
    return ''.join(c for c in value if c.isprintable())[:limit]


def ip(value):
    try:return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:return ''


def context(environ,data):
    peer=ip(environ.get('REMOTE_ADDR',''));forwarded=''
    # Diagnostic only: deployment-specific proxy trust is not established here.
    # Never use this header for authorization, bans or rate-limit bypasses.
    raw=environ.get('HTTP_X_FORWARDED_FOR','')
    if isinstance(raw,str) and len(raw)<=2048:forwarded=ip(raw.split(',')[0])
    ua=clean(environ.get('HTTP_USER_AGENT',''),300)
    browser='Не определён'
    for pattern,name in ((r'Edg(?:A|iOS)?/([\d.]+)','Edge'),(r'OPR/([\d.]+)','Opera'),(r'(?:Firefox|FxiOS)/([\d.]+)','Firefox'),(r'(?:Chrome|CriOS)/([\d.]+)','Chrome'),(r'Version/([\d.]+).*Safari','Safari')):
        match=re.search(pattern,ua)
        if match:browser=name+' '+match[1][:24];break
    os_name='Не определена'
    for pattern,name in (('Android','Android'),('iPhone|iPad','iOS'),('Windows NT','Windows'),('Macintosh|Mac OS X','macOS'),('Linux','Linux')):
        if re.search(pattern,ua):os_name=name;break
    device=data.get('device',{}) if isinstance(data,dict) else {}
    if not isinstance(device,dict):device={}
    device_id=device.get('id','')
    device_hash=digest(device_id) if isinstance(device_id,str) and re.fullmatch(r'[A-Za-z0-9_-]{16,80}',device_id) else ''
    return {'ip':forwarded or peer,'peer':peer,'ipSource':'proxy_header_unverified' if forwarded else 'connection',
            'browser':browser,'os':os_name,'agent':ua,'deviceHash':device_hash,'deviceName':clean(device.get('name'),80)}


class Security:
    def __init__(self,service):
        self.service=service;self.db=service.db;self.now=service.now;self.audit_failed=False
        with self.db.transaction() as tx:
            tx.execute("CREATE TABLE IF NOT EXISTS security_events(id TEXT PRIMARY KEY,created BIGINT NOT NULL,actor TEXT NOT NULL,role TEXT NOT NULL,channel TEXT NOT NULL,action TEXT NOT NULL,result TEXT NOT NULL,certificate TEXT NOT NULL,product TEXT NOT NULL,metadata TEXT NOT NULL,flags TEXT NOT NULL)")
            tx.execute('CREATE INDEX IF NOT EXISTS security_events_created ON security_events(created)')
            tx.execute('CREATE INDEX IF NOT EXISTS security_events_actor ON security_events(actor,channel,result,created)')
            tx.execute("CREATE TABLE IF NOT EXISTS developer_certificate(id INTEGER PRIMARY KEY CHECK(id=1),player TEXT NOT NULL,product TEXT NOT NULL,certificate TEXT NOT NULL,created BIGINT NOT NULL)")
            tx.execute("INSERT INTO developer_certificate VALUES(1,'','','',0) ON CONFLICT(id) DO NOTHING")
            tx.execute("CREATE TABLE IF NOT EXISTS registration_claims(request_id TEXT PRIMARY KEY,grant_type TEXT NOT NULL,payment_status TEXT NOT NULL,payment_availability TEXT NOT NULL,decision_reason TEXT NOT NULL DEFAULT '',decision_reference TEXT NOT NULL DEFAULT '')")
    def binding(self,tx):return tx.one('SELECT * FROM developer_certificate WHERE id=1')
    def guard(self,tx,player,product,certificate):
        owner=self.service.owner
        if not owner or player!=owner['player']:return
        b=self.binding(tx)
        if b['certificate'] and (b['player'],b['product'],b['certificate'])!=(player,product,certificate):
            raise Problem(403,'Сертификат владельца не совпадает с единственным закреплённым сертификатом.',{'code':'developer_certificate_mismatch'})
    def pin(self,tx,player,product,certificate):
        if not self.service.owner or player!=self.service.owner['player']:raise Problem(403,'Только владелец может закрепить сертификат')
        row=tx.one("UPDATE developer_certificate SET player=?,product=?,certificate=?,created=CASE WHEN certificate='' THEN ? ELSE created END WHERE id=1 AND (certificate='' OR (player=? AND product=? AND certificate=?)) RETURNING id",(player,product,certificate,int(self.now()),player,product,certificate))
        if row is None:raise Problem(403,'Другой сертификат владельца уже закреплён.',{'code':'developer_certificate_mismatch'})
    def replace_binding(self,token,data):
        product=ident(data.get('productId'));certificate=ident(data.get('certificateId'),128)
        reg=self.service.registration
        with self.db.transaction() as tx:reg.authorize(tx,token)
        reg.limit('developer-binding-password',900,5)
        if not self.service.owner or not password_matches(data.get('password'),self.service.owner['hash']):raise Problem(403,'Пароль владельца неверен')
        owner=self.service.owner
        with self.db.transaction() as tx:
            reg.authorize(tx,token)
            b=tx.one('SELECT * FROM developer_certificate WHERE id=1'+(' FOR UPDATE' if tx.postgres else ''))
            if data.get('previousCertificateId','')!=b['certificate']:raise Problem(409,'Закрепление изменилось. Обновите кабинет.')
            active=tx.one('SELECT c.id FROM certificates c JOIN players p ON p.id=c.player WHERE c.id=? AND c.product=? AND c.player=? AND c.active=1 AND p.active=1 AND p.phone=?',(certificate,product,owner['player'],owner['phone']))
            if not active:raise Problem(403,'Сначала зарегистрируйте этот сертификат на аккаунт владельца')
            tx.execute('UPDATE developer_certificate SET player=?,product=?,certificate=?,created=? WHERE id=1',(owner['player'],product,certificate,int(self.now())))
            tx.execute("UPDATE sessions SET state='expired',expires=0 WHERE player=? AND (certificate<>? OR product<>?)",(owner['player'],certificate,product))
        return {'status':'saved'}
    def claim(self,tx,rid,certificate,data):
        payment=certificate.get('payment',{})
        availability=data.get('paymentAvailability','unknown')
        if availability not in ('unknown','available','unavailable','not_required'):availability='unknown'
        tx.execute('INSERT INTO registration_claims(request_id,grant_type,payment_status,payment_availability) VALUES(?,?,?,?)',
                   (rid,clean(certificate.get('grantType'),24),clean(payment.get('status') if isinstance(payment,dict) else '',40),availability))
    def event(self,actor,role,channel,action,result,meta,certificate='',product='',flags=()):
        now=int(self.now());flags=list(flags)
        with self.db.transaction() as tx:
            tx.execute('DELETE FROM security_events WHERE created<?',(now-2592000,))
            # Only successful authenticated logins establish the comparison baseline.
            previous=tx.one("SELECT metadata FROM security_events WHERE actor=? AND channel=? AND result='verified' ORDER BY created DESC,id DESC LIMIT 1",(actor,channel))
            if previous:
                old=json.loads(previous['metadata'])
                if meta['ip'] and old.get('ip') and (meta['ip'],meta['ipSource'])!=(old['ip'],old.get('ipSource')):flags.append('different_ip')
                if meta['deviceHash'] and old.get('deviceHash') and meta['deviceHash']!=old['deviceHash']:flags.append('different_device')
                if meta['browser']!='Не определён' and old.get('browser') and meta['browser']!=old['browser']:flags.append('different_browser')
            elif result=='verified':flags.append('first_observed_login')
            if meta['ipSource']=='proxy_header_unverified':flags.append('ip_unverified')
            tx.execute('INSERT INTO security_events VALUES(?,?,?,?,?,?,?,?,?,?,?)',(secrets.token_hex(16),now,clean(actor,32),role,channel,action,result,clean(certificate,128),clean(product,100),json.dumps(meta,ensure_ascii=False),json.dumps(list(dict.fromkeys(flags)))))
            tx.execute('DELETE FROM security_events WHERE id NOT IN (SELECT id FROM security_events ORDER BY created DESC,id DESC LIMIT 10000)')
    def observe(self,environ,data,status,result,token):
        path=environ.get('PATH_INFO','');method=environ.get('REQUEST_METHOD','GET')
        if method!='POST' or status in (413,415,429) or not isinstance(data,dict):return
        if path.startswith('/api/moderation/') and path!='/api/moderation/login':
            try:
                with self.db.transaction() as tx:self.service.registration.authorize(tx,token)
            except Problem:return
        meta=context(environ,data);ok=status==200;owner=self.service.owner
        action='';actor='';role='unverified';channel='player';cert='';product='';flags=[];outcome='accepted' if ok else 'denied'
        if path=='/api/moderation/login':
            actor=owner['player'] if owner else '';role='owner' if ok else 'unverified';channel='moderator';action='moderator_login';outcome='verified' if ok else 'denied'
            if not ok:flags.append('login_failed')
        elif path=='/api/sessions':
            if status==400:return
            action='session_request';actor=clean(data.get('playerId'),32);cert=clean(data.get('certificateId'),128);product=clean(data.get('productId'),100)
            if data.get('grantType')=='developer':flags.append('developer_claim')
            if not ok:
                code=result.get('code','')
                flags.append('developer_mismatch' if code=='developer_certificate_mismatch' else 'certificate_denied')
        elif path=='/api/registrations':
            action='registration_request';c=data.get('certificate',{});c=c if isinstance(c,dict) else {}
            actor=clean(c.get('playerId'),32);cert=clean(c.get('certificateId'),128);product=clean(c.get('productId'),100)
            if c.get('grantType')=='developer':flags.append('developer_claim_blocked')
            flags.append('payment_not_verified')
            if data.get('paymentAvailability')=='unavailable':flags.append('payment_unavailable_reported')
        else:
            match=re.fullmatch(r'/api/sessions/([a-f0-9]{32})/(code|owner-password|phone)',path)
            if match:
                with self.db.transaction() as tx:s=tx.one('SELECT * FROM sessions WHERE id=?',(match[1],))
                if not s or not token or not hmac.compare_digest(s['web_hash'],digest(token)):return
                if match[2]=='phone':return
                action='player_login';actor=s['player'];cert=s['certificate'];product=s['product'];outcome='verified' if ok and result.get('status')=='verified' else 'denied'
                role=('owner' if owner and actor==owner['player'] and match[2]=='owner-password' else 'player') if outcome=='verified' else 'unverified'
                if outcome=='denied':flags.append('login_failed')
            elif path in ('/api/moderation/developer-certificate','/api/moderation/logout-others'):
                actor=owner['player'] if owner else '';role='owner';channel='moderator';action='developer_binding' if path.endswith('developer-certificate') else 'revoke_other_sessions'
                cert=clean(data.get('certificateId'),128);product=clean(data.get('productId'),100)
            else:
                decision=re.fullmatch(r'/api/moderation/([a-f0-9]{32})/(approve|reject)',path)
                if not decision:return
                with self.db.transaction() as tx:
                    request=tx.one('SELECT player,certificate,product FROM registration_requests WHERE id=?',(decision[1],))
                if not request:return
                actor=owner['player'] if owner else '';role='owner';channel='moderator';action='registration_'+decision[2]
                cert=request['certificate'];product=request['product'];meta['subjectPlayer']=request['player']
                if ok and decision[2]=='approve':
                    meta['accessReason']=clean(data.get('accessReason','manual_access'),24)
                    meta['paymentReference']=clean(data.get('paymentReference',''),120)
                    flags.append('payment_not_verified')
        self.event(actor,role,channel,action,outcome,meta,cert,product,flags)
    def overview(self,token,before=None):
        reg=self.service.registration
        with self.db.transaction() as tx:
            reg.authorize(tx,token)
            query='SELECT * FROM security_events WHERE created>=?';args=[int(self.now())-2592000]
            if before:
                stamp,key=before
                query+=' AND (created<? OR (created=? AND id<?))';args.extend([stamp,stamp,key])
            cursor=tx.execute(query+' ORDER BY created DESC,id DESC LIMIT 100',args);names=[c[0] for c in cursor.description]
            events=[dict(zip(names,row)) for row in cursor.fetchall()]
            for e in events:e['metadata']=json.loads(e['metadata']);e['flags']=json.loads(e['flags'])
            b=self.binding(tx);b=b if b['certificate'] else None
            candidates=[]
            if self.service.owner:
                cursor=tx.execute('SELECT id,product FROM certificates WHERE player=? AND active=1 ORDER BY id LIMIT 100',(self.service.owner['player'],))
                candidates=[{'id':row[0],'product':row[1]} for row in cursor.fetchall()]
        last=events[-1] if len(events)==100 else None
        return {'events':events,'developerCertificate':b,'ownerCertificates':candidates,'retentionDays':30,'auditHealthy':not self.audit_failed,'next':{'created':last['created'],'id':last['id']} if last else None}
