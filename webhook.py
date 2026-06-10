import json
import os
import threading
import urllib.parse
import urllib.request
import urllib.error

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse


app = FastAPI()

BOT_TOKEN = os.environ.get('BOT_TOKEN')
GH_TOKEN = os.environ.get('GH_TOKEN')
GH_REPO = os.environ.get('GH_REPO')

if not BOT_TOKEN or not GH_TOKEN or not GH_REPO:
    print('WARNING: Missing one or more required env vars (BOT_TOKEN, GH_TOKEN, GH_REPO)')


def send_telegram(chat_id, text):
    if not BOT_TOKEN:
        print('ERROR: BOT_TOKEN not set')
        return
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage'
    data = urllib.parse.urlencode({
        'chat_id': chat_id, 'text': text, 'parse_mode': 'HTML'
    }).encode()
    req = urllib.request.Request(url, data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            resp = json.loads(r.read().decode())
            if not resp.get('ok'):
                print(f'Telegram API error: {resp}')
    except Exception as e:
        print(f'send_telegram failed: {e}')


def trigger_workflow_vuln(domain):
    if not GH_TOKEN or not GH_REPO:
        print('ERROR: GH_TOKEN or GH_REPO not set')
        return
    url = f'https://api.github.com/repos/{GH_REPO}/actions/workflows/vuln_scan.yml/dispatches'
    payload = json.dumps({'ref': 'main', 'inputs': {'domain': domain}}).encode()
    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header('Authorization', f'Bearer {GH_TOKEN}')
    req.add_header('Accept', 'application/vnd.github.v3+json')
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent', 'recon-bot')
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f'Vuln workflow triggered: {r.status}')
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f'GitHub API error {e.code}: {body}')
    except Exception as e:
        print(f'trigger_workflow_vuln failed: {e}')


def trigger_workflow(domain):
    if not GH_TOKEN or not GH_REPO:
        print('ERROR: GH_TOKEN or GH_REPO not set')
        return
    url = f'https://api.github.com/repos/{GH_REPO}/actions/workflows/recon.yml/dispatches'
    payload = json.dumps({'ref': 'main', 'inputs': {'domain': domain}}).encode()
    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header('Authorization', f'Bearer {GH_TOKEN}')
    req.add_header('Accept', 'application/vnd.github.v3+json')
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent', 'recon-bot')
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f'Workflow triggered: {r.status}')
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f'GitHub API error {e.code}: {body}')
    except Exception as e:
        print(f'trigger_workflow failed: {e}')


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

    elif text.startswith('/vuln '):
        domain = text[5:].strip()
        if not domain or '.' not in domain:
            send_telegram(chat_id, 'Usage: /vuln example.com')
            return JSONResponse({'ok': True})

        send_telegram(chat_id,
            f'\U0001F525 Vuln scan started for <code>{domain}</code>!\n'
            f'Results will appear in your channel in a few minutes.')

        threading.Thread(target=trigger_workflow_vuln, args=(domain,), daemon=True).start()

    elif text in ['/start', '/help']:
        send_telegram(chat_id,
            '\U0001F50D <b>Domain Recon Bot</b>\n\n'
            'Commands:\n'
            '<code>/domain example.com</code> - Recon (subs, ports, Exchange)\n'
            '<code>/vuln example.com</code> - Vuln scan (Exchange CVEs, dir brute, RDP, default creds)\n'
            '<code>/help</code> - Show this\n\n'
            'Results will be posted to your Telegram channel.')

    return JSONResponse({'ok': True})


@app.get('/', response_class=HTMLResponse)
async def root():
    return '''
    <html><body style="background:#111;color:#0f0;font-family:monospace;padding:40px">
    <h1>Recon Bot is running</h1>
    <p>Set webhook: <a href="/setup">/setup</a></p>
    </body></html>
    '''


@app.get('/webhookinfo')
async def webhook_info():
    if not BOT_TOKEN:
        return {'error': 'BOT_TOKEN not set'}
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/getWebhookInfo'
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            result = json.loads(r.read().decode())
            return result
    except Exception as e:
        return {'error': str(e)}


@app.get('/setup')
async def setup(request: Request):
    host = os.environ.get('RENDER_EXTERNAL_URL',
        str(request.base_url).rstrip('/'))
    webhook_url = f'{host}/webhook'

    url = f'https://api.telegram.org/bot{BOT_TOKEN}/setWebhook'
    data = urllib.parse.urlencode({'url': webhook_url}).encode()
    req = urllib.request.Request(url, data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req, timeout=10) as r:
        result = json.loads(r.read().decode())

    return {
        'webhook_url': webhook_url,
        'telegram_response': result,
    }
