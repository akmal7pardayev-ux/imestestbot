import json
import os
import sys
import urllib.parse
import urllib.request
import urllib.error


BOT_TOKEN_ENV = 'BOT_TOKEN'
GH_TOKEN_ENV = 'GH_TOKEN'
GH_REPO_ENV = 'GH_REPO'
OFFSET_FILE = 'offset.json'


def get_updates(bot_token, offset=None):
    url = f'https://api.telegram.org/bot{bot_token}/getUpdates'
    params = {'timeout': 5}
    if offset:
        params['offset'] = offset
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def send_message(bot_token, chat_id, text):
    url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
    params = {'chat_id': chat_id, 'text': text, 'parse_mode': 'HTML'}
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def trigger_workflow(gh_token, gh_repo, domain):
    url = f'https://api.github.com/repos/{gh_repo}/actions/workflows/recon.yml/dispatches'
    payload = json.dumps({'ref': 'main', 'inputs': {'domain': domain}}).encode()
    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header('Authorization', f'Bearer {gh_token}')
    req.add_header('Accept', 'application/vnd.github.v3+json')
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent', 'recon-bot')
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status == 204
    except urllib.error.HTTPError as e:
        print(f'GitHub API error: {e.code} {e.read().decode()}')
        return False


def load_offset():
    if os.path.exists(OFFSET_FILE):
        with open(OFFSET_FILE) as f:
            return json.load(f).get('offset', 0)
    return 0


def save_offset(offset):
    with open(OFFSET_FILE, 'w') as f:
        json.dump({'offset': offset}, f)


def main():
    bot_token = os.environ.get(BOT_TOKEN_ENV)
    gh_token = os.environ.get(GH_TOKEN_ENV)
    gh_repo = os.environ.get(GH_REPO_ENV)

    if not all([bot_token, gh_token, gh_repo]):
        print('Missing BOT_TOKEN, GH_TOKEN, or GH_REPO')
        sys.exit(1)

    offset = load_offset()

    updates = get_updates(bot_token, offset + 1 if offset else None)
    if not updates.get('ok') or not updates.get('result'):
        return

    for update in updates['result']:
        update_id = update['update_id']
        msg = update.get('message', {})
        text = msg.get('text', '').strip()
        chat_id = msg.get('chat', {}).get('id')

        if not text or not chat_id:
            continue

        if text.startswith('/domain '):
            domain = text[8:].strip()
            if not domain or '.' not in domain:
                send_message(bot_token, chat_id, 'Usage: /domain example.com')
                continue

            send_message(bot_token, chat_id,
                f'\U0001F680 Recon started for <code>{domain}</code>!\n'
                f'Results will appear in your channel in a few minutes.')

            if trigger_workflow(gh_token, gh_repo, domain):
                print(f'Triggered recon for {domain}')
            else:
                send_message(bot_token, chat_id, '\U0000274C Failed to trigger recon. Check GH_TOKEN.')

        elif text in ['/start', '/help']:
            send_message(bot_token, chat_id,
                '\U0001F50D <b>Domain Recon Bot</b>\n\n'
                'Commands:\n'
                '<code>/domain example.com</code> - Start deep recon\n'
                '<code>/help</code> - Show this\n\n'
                'Results will be posted to your Telegram channel.')

        offset = update_id

    save_offset(offset)
    print(f'Processed, offset: {offset}')


if __name__ == '__main__':
    main()
