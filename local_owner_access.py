"""Open the downloaded DevFlow project using local owner access."""
from pathlib import Path
import os
import threading
import time
import urllib.request
import webbrowser

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)

def main():
    import json
    try:
        with urllib.request.urlopen('http://127.0.0.1:8000/owner/status', timeout=2) as response:
            existing = json.load(response)
    except Exception:
        existing = None
    if existing is not None:
        if existing.get('enabled') and existing.get('owner_email') == 'bhuvanjakkula@gmail.com':
            webbrowser.open('http://127.0.0.1:8000/engineering')
            return
        raise RuntimeError('Port 8000 is already in use by another service. Close it before starting local DevFlow.')
    if os.environ.get('DEVFLOW_ENTERPRISE_MODE') == '1':
        raise RuntimeError('Enterprise mode is configured. Use the enterprise deployment instead of this local owner launcher.')
    os.environ['DEVFLOW_OWNER_MODE'] = '1'
    os.environ['DEVFLOW_PUBLIC_OWNER_MODE'] = '0'
    os.environ['DEVFLOW_DB'] = str(ROOT / 'data' / 'devflow.sqlite3')
    from app.owner_access import issue_link, OWNER_EMAIL
    import uvicorn
    link = issue_link()
    print('DevFlow local owner: ' + OWNER_EMAIL, flush=True)
    print('Project location: ' + str(ROOT), flush=True)
    print('One-use owner link (expires in five minutes): ' + link, flush=True)

    def open_when_ready():
        for _ in range(80):
            try:
                with urllib.request.urlopen('http://127.0.0.1:8000/owner/status', timeout=1) as response:
                    if response.status == 200:
                        webbrowser.open(link)
                        return
            except Exception:
                time.sleep(0.25)

    threading.Thread(target=open_when_ready, daemon=True).start()
    uvicorn.run('app.main:app', host='127.0.0.1', port=8000, reload=False, access_log=False)

if __name__ == '__main__':
    main()
