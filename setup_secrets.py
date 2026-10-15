"""Local setup. Creates private config files, never sends passwords to a service."""
import base64
import getpass
import json
import os
from pathlib import Path
import secrets
from identity_server import digest,password_hash,phone,ident

def main():
    print('MyEngine R21. Локальная настройка владельца и одного Android-шлюза.')
    player=ident(input('ID владельца из сертификата: ').strip(),32)
    number=phone(input('Телефон владельца (+кодстраныномер): ').strip())
    first=getpass.getpass('Придумай пароль владельца (12–128 символов): ')
    if first!=getpass.getpass('Повтори пароль: '):raise ValueError('Пароли не совпадают')
    hashed=password_hash(first);first=None
    directory=Path('private-config')
    directory.mkdir(mode=0o700,exist_ok=True)
    render=directory/'render-secrets.env';android=directory/'phone-token.txt'
    if render.exists() or android.exists():raise ValueError('private-config уже содержит настройки. Сохрани их перед созданием новых.')
    token=secrets.token_urlsafe(32)
    values={'SMS_PROVIDER':'phone','SMS_ENABLED':'false','GATEWAY_TOKEN_HASH':digest(token),
        'OTP_KEY':base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),'OWNER_PLAYER_ID':player,'OWNER_PHONE':number,'OWNER_PASSWORD_HASH':hashed}
    def write(path,text):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as stream:stream.write(text)
    write(render,''.join(key+'='+value+'\n' for key,value in values.items()))
    write(android,token+'\n')
    print('Готово: private-config/render-secrets.env — значения для Render; phone-token.txt — ключ для Android.')
    print('Пароль не сохранён. Эти файлы не загружай в GitHub и не отправляй игрокам. SMS пока выключены.')

if __name__=='__main__':main()
