"""Run privately with DATABASE_URL. No public registration endpoint."""
import argparse
import getpass
import json
import os
from pathlib import Path
from identity_server import Database

def main():
    parser=argparse.ArgumentParser(description='Register a player/certificate only after the author checked the purchase or developer grant.')
    parser.add_argument('operation',choices=['grant','revoke-player','revoke-certificate'])
    parser.add_argument('--certificate',help='Path to the issued JSON for grant; certificate ID for revoke-certificate')
    parser.add_argument('--player',help='Player ID for revoke-player')
    args=parser.parse_args()
    url=os.environ.get('DATABASE_URL','')
    if not url.startswith(('postgres://','postgresql://')):parser.error('Set the private PostgreSQL DATABASE_URL in your environment')
    database=Database(url);database.initialize()
    if args.operation=='grant':
        if not args.certificate:parser.error('--certificate is required')
        path=Path(args.certificate)
        if path.stat().st_size>65536:parser.error('Certificate too large')
        value=json.loads(path.read_text(encoding='utf-8-sig'))
        if value.get('schema')!='myengine-license/v1' or value.get('licenseStatus')!='issued':parser.error('Unsupported certificate')
        number=getpass.getpass('Registered player phone (+country number), input hidden: ').strip()
        database.grant(value['playerId'],number,value['productId'],value['certificateId'])
        print('Player and certificate registered. No SMS was sent.')
    elif args.operation=='revoke-player':
        if not args.player:parser.error('--player is required')
        with database.transaction() as tx:
            tx.execute('UPDATE players SET active=0 WHERE id=?',(args.player,))
            tx.execute("UPDATE sessions SET state='expired',expires=0 WHERE player=?",(args.player,))
        print('Player revoked.')
    else:
        if not args.certificate:parser.error('--certificate is required')
        with database.transaction() as tx:
            tx.execute('UPDATE certificates SET active=0 WHERE id=?',(args.certificate,))
            tx.execute("UPDATE sessions SET state='expired',expires=0 WHERE certificate=?",(args.certificate,))
        print('Certificate revoked.')

if __name__=='__main__':main()
