"""Create a clean source release excluding secrets, databases and Git metadata."""
import hashlib
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

root = Path(__file__).resolve().parent
target = root.parent.parent / 'DevFlow12-OpenAI-Assistance-v0.19.zip'
excluded = {'.git', '__pycache__', '.pytest_cache', '.venv', 'data', 'node_modules', '.pqc-deps', '.auth-deps', '.quality-deps', '.enterprise-deps', '.runtime-deps', '.ruff_cache', '.bin', 'secrets'}
with ZipFile(target, 'w', ZIP_DEFLATED) as archive:
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if path.name.startswith('.env') or path.suffix in {'.log', '.db', '.sqlite', '.sqlite3', '.key', '.pem', '.dfbackup', '.crt'} or path.name.endswith(('-wal', '-shm', '-journal')) or path.name == 'private.pqc.json' or path.name.endswith('.pqc.envelope.json') or any(p in excluded or p.startswith(('.test', '.backup-', '.recovery-', 'pqc_keys')) for p in relative.parts):
            continue
        archive.write(path, 'devflow12/' + relative.as_posix())
checksum = hashlib.sha256(target.read_bytes()).hexdigest()
target.with_suffix('.zip.sha256').write_text(checksum + '  ' + target.name + '\n', encoding='ascii')
print(f'{target}\nSHA256 {checksum}')
