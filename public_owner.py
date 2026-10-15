"""Run an email-protected temporary tunnel; never fall back to an open tunnel."""
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import queue

from app.owner_access import OWNER_EMAIL


def main():
    root = Path(__file__).resolve().parent
    client = root / '.bin' / 'cloudflared.exe'
    if not client.is_file():
        raise SystemExit('Install the official cloudflared Windows client in .bin/cloudflared.exe.')
    help_text = subprocess.check_output([str(client), 'tunnel', '--help'], text=True)
    if '--allowed-mail' not in help_text:
        raise SystemExit('This client does not support protected tunnels. Update cloudflared first.')
    # Use an isolated origin port so the local owner server can keep running.
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    secret_host = secrets.token_hex(32) + '.localhost'
    tunnel = subprocess.Popen([str(client), 'tunnel', '--url', f'http://127.0.0.1:{port}',
                               '--allowed-mail', OWNER_EMAIL, '--http-host-header', secret_host],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                              cwd=root, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    lines = queue.Queue(maxsize=128)
    def read_output():
        for line in tunnel.stdout:
            try:
                lines.put_nowait(line)
            except queue.Full:
                pass  # Keep draining subprocess output without unbounded log accumulation.
    threading.Thread(target=read_output, daemon=True).start()
    server = None
    try:
        deadline = time.monotonic() + 90
        url = None
        while time.monotonic() < deadline and tunnel.poll() is None:
            try:
                line = lines.get(timeout=1)
            except queue.Empty:
                continue
            match = re.search(r'https://[a-z0-9-]+\.trycloudflare\.com', line)
            if match:
                url = match.group(0)
                break
        if not url:
            raise SystemExit('Protected tunnel failed to start. No public origin server was started.')
        environment = os.environ.copy()
        environment.update(DEVFLOW_OWNER_MODE='0', DEVFLOW_PUBLIC_OWNER_MODE='1',
                           DEVFLOW_TUNNEL_HOST=secret_host, DEVFLOW_PUBLIC_ORIGIN=url)
        server = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app.main:app', '--host',
                                   '127.0.0.1', '--port', str(port), '--no-access-log',
                                   '--no-proxy-headers'], cwd=root, env=environment,
                                  creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        print('Owner-only public DevFlow: ' + url, flush=True)
        print('Sign in with ' + OWNER_EMAIL + ' and the emailed PIN. Keep this launcher running.', flush=True)
        (root / 'data').mkdir(exist_ok=True)
        (root / 'data' / 'public-url.txt').write_text(url, encoding='utf-8')
        while tunnel.poll() is None and server.poll() is None:
            time.sleep(1)
        raise SystemExit('Public access stopped because the tunnel or server exited.')
    except KeyboardInterrupt:
        pass
    finally:
        for process in (server, tunnel):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        url_file = root / 'data' / 'public-url.txt'
        if url_file.exists():
            url_file.unlink()


if __name__ == '__main__':
    main()
