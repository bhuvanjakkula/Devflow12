"""Offline PQC keys and protected report exchange. Passwords are prompted, never CLI arguments."""
import argparse
import getpass
import json
from pathlib import Path

from app.pqc_export import generate_keys, protect_keys, unlock_keys, seal, open_report, verify_envelope, key_id


def read(path):
    path = Path(path)
    if path.stat().st_size > 12000000:
        raise ValueError('Input file too large')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def write(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    gen = commands.add_parser('keygen')
    gen.add_argument('--directory', required=True, type=Path)
    seal_cmd = commands.add_parser('seal')
    seal_cmd.add_argument('--report', required=True)
    seal_cmd.add_argument('--private', required=True)
    seal_cmd.add_argument('--recipient', required=True)
    seal_cmd.add_argument('--output', required=True)
    decrypt = commands.add_parser('open')
    decrypt.add_argument('--envelope', required=True)
    decrypt.add_argument('--private', required=True)
    decrypt.add_argument('--sender', required=True)
    decrypt.add_argument('--output', required=True)
    verify = commands.add_parser('verify')
    verify.add_argument('--envelope', required=True)
    verify.add_argument('--sender', required=True)
    args = parser.parse_args()
    if args.command == 'keygen':
        password = getpass.getpass('Strong key passphrase (16+ characters): ')
        if password != getpass.getpass('Repeat passphrase: '):
            raise ValueError('Passphrases differ')
        public, private = generate_keys()
        protected = protect_keys(private, password)
        args.directory.mkdir(parents=True, exist_ok=False)
        write(args.directory / 'private.pqc.json', protected)
        write(args.directory / 'public.pqc.json', public)
        print('Public key fingerprint: ' + key_id(public))
    elif args.command == 'verify':
        verify_envelope(read(args.envelope), read(args.sender))
        print('Signature verified against the supplied trusted sender key.')
    else:
        private = unlock_keys(read(args.private), getpass.getpass('Key passphrase: '))
        result = seal(read(args.report), private, read(args.recipient)) if args.command == 'seal' else open_report(read(args.envelope), private, read(args.sender))
        write(args.output, result)
        print('Output written; existing files are never overwritten.')


if __name__ == '__main__':
    main()
