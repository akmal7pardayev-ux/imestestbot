import json
import os
import threading
import urllib.parse
import urllib.request
import urllib.error

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


app = FastAPI()

BOT_TOKEN = os.environ.get('BOT_TOKEN', '')
GH_TOKEN = os.environ.get('GH_TOKEN', '')
GH_REPO = os.environ.get('GH_REPO', '')


def send_telegram(chat_id, text):
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage'
    data = urllib.parse.urlencode({
        'chat_id': chat_id, 'text': text, 'parse_mode': 'HTML'
    }).encode()
    req = urllib.request.Request(url, data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req, timeout=10):
        pass


def trigger_workflow(domain):
    url = f'https://api.github.com/repos/{GH_REPO}/actions/workflows/recon.yml/dispatches'
    payload = json.dumps({'ref': 'main', 'inputs': {'domain': domain}}).encode()
    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header('Authorization', f'Bearer {GH_TOKEN}')
    req.add_header('Accept', 'application/vnd.github.v3+json')
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent', 'recon-bot')
    with urllib.request.urlopen(req, timeout=15):
        pass


@app.post('/webhook')
async def webhook(request: Request):
    update = await request.json()
    msg = update.get('message', {})
    text = msg.get('text', '').strip()
    chat_id = msg.get('chat', {}).get('id')

    if not text or not chat_id:
        return JSONResponse({'ok': True})

    if text.startswith('/domain '):
        domain = text[8:].strip()
        if not domain or '.' not in domain:
            send_telegram(chat_id, 'Usage: /domain example.com')
            return JSONResponse({'ok': True})

        send_telegram(chat_id,
            f'\U0001F680 Recon started for <code>{domain}</code>!\n'
            f'Results will appear in your channel in a few minutes.')

        threading.Thread(target=trigger_workflow, args=(domain,), daemon=True).start()

    elif text in ['/start', '/help']:
        send_telegram(chat_id,
            '\U0001F50D <b>Domain Recon Bot</b>\n\n'
            'Commands:\n'
            '<code>/domain example.com</code> - Start deep recon\n'
            '<code>/help</code> - Show this\n\n'
            'Results will be posted to your Telegram channel.')

    return JSONResponse({'ok': True})


@app.get('/')
async def root():
    return {'status': 'running'}


@app.get('/setup')
async def setup():
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/setWebhook'
    host = os.environ.get('RENDER_EXTERNAL_URL', 'https://example.com')
    webhook_url = f'{host}/webhook'
    data = urllib.parse.urlencode({'url': webhook_url}).encode()
    req = urllib.request.Request(url, data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req, timeout=10) as r:
        result = json.loads(r.read().decode())
    return result
