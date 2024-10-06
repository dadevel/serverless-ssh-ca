from argparse import ArgumentParser, Namespace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, TextIO
import json
import os
import subprocess
import sys

from sshca.s3 import S3Client
from sshca.ca import CertificateAuthority, Signature


def main() -> None:
    if os.environ.get('SSH_ASKPASS') == sys.argv[0]:
        command_ssh_askpass()
        return

    bucket = os.environ.get('SSHCA_BUCKET')

    entrypoint = ArgumentParser()
    entrypoint.add_argument('--debug', action='store_const', const=True, default=False)

    parsers = entrypoint.add_subparsers(dest='command', required=True)

    parser = parsers.add_parser('init')
    parser.add_argument('-b', '--bucket', required=not bucket, default=bucket)
    parser.add_argument('--force', action='store_const', default=False, const=True)

    parser = parsers.add_parser('sign', epilog="note: TIMESPEC format is described under 'validity_interval' in ssh-keygen manpage")
    parser.add_argument('-b', '--bucket', required=not bucket, default=bucket, metavar='BUCKET')
    parser.add_argument('-k', '--pubkey', required=True, metavar='BLOB|FILE')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--user', metavar='USERNAME')
    group.add_argument('-f', '--host', metavar='HOSTFQDN')
    parser.add_argument('-r', '--role', action='append', default=[], metavar='ROLENAME')
    parser.add_argument('-v', '--validity', default='+30d', metavar='TIMESPEC')

    parser = parsers.add_parser('revoke')
    parser.add_argument('-b', '--bucket', required=not bucket, default=bucket)
    parser.add_argument('-s', '--serial', type=int, metavar='NUMBER')

    parser = parsers.add_parser('get-pubkey')
    parser.add_argument('-b', '--bucket', required=not bucket, default=bucket)

    parser = parsers.add_parser('get-log')
    parser.add_argument('-b', '--bucket', required=not bucket, default=bucket)

    parser = parsers.add_parser('get-krl')
    parser.add_argument('-b', '--bucket', required=not bucket, default=bucket)
    parser.add_argument('-r', '--raw', action='store_const', const=True, default=False)

    parser = parsers.add_parser('terraform')

    opts = entrypoint.parse_args()
    function = globals()[f'command_{opts.command.replace('-', '_')}']
    try:
        function(opts)
    except Exception as e:
        if opts.debug:
            raise
        print(f'{e.__class__.__name__}: {e}', file=sys.stderr)
        exit(1)


def command_init(opts: Namespace) -> None:
    ca = CertificateAuthority(S3Client(opts.bucket))
    ca.initialize(overwrite=opts.force)


def command_sign(opts: Namespace) -> None:
    ca = CertificateAuthority(S3Client(opts.bucket))

    pubkey_path = Path(opts.pubkey)
    if pubkey_path.is_file():
        pubkey = pubkey_path.read_text()
    elif opts.pubkey.startswith('ssh-'):
        pubkey = opts.pubkey
    else:
        raise ValueError(f'pubkey {opts.pubkey!r} invalid')

    if opts.user:
        sig = ca.sign_user(pubkey, opts.user, opts.role, opts.validity)
    elif opts.host:
        sig = ca.sign_host(pubkey, opts.host, opts.validity)
    else:
        raise RuntimeError('unreachable')

    if pubkey_path.is_file():
        cert_path = pubkey_path.with_name(pubkey_path.name.removesuffix('.pub') + '-cert.pub')
        cert_path.write_text(sig['certificate'])
        sig.update(path=cert_path.as_posix())

    json_dump(sig, sys.stdout)


def command_revoke(opts: Namespace) -> None:
    ca = CertificateAuthority(S3Client(opts.bucket))
    ca.revoke(opts.serial)


def command_get_pubkey(opts: Namespace) -> None:
    ca = CertificateAuthority(S3Client(opts.bucket))
    sys.stdout.buffer.write(ca.get_pubkey())


def command_get_log(opts: Namespace) -> None:
    ca = CertificateAuthority(S3Client(opts.bucket))
    for sig in ca.get_log():
        json_dump(sig, sys.stdout)


def command_get_krl(opts: Namespace) -> None:
    ca = CertificateAuthority(S3Client(opts.bucket))
    content = ca.get_krl()
    if opts.raw:
        sys.stdout.buffer.write(content)
    else:
        subprocess.run(['ssh-keygen', '-Q', '-l', '-f', '/dev/stdin'], input=content)


def find_certificate(sigs: Iterable[Signature], wanted_pubkey: str, renew_interval: int) -> Signature|None:
    now = datetime.now(tz=timezone.utc)
    for sig in sigs:
        if wanted_pubkey != sig['pubkey']:
            continue
        expired = not (sig['valid_after'] <= now < sig['valid_before'])
        if expired:
            continue
        about_to_expire = now + timedelta(days=renew_interval) > sig['valid_before']
        if about_to_expire:
            continue

        # TODO: get new cert if principals changed, revoke old cert
        # TODO: get new cert if fqdn/username changed, revoke old cert

        return sig


def command_terraform(opts: Namespace) -> None:
    bucket = os.environ.get('SSHCA_BUCKET')
    if not bucket:
        raise InvocationError('env var SSHCA_BUCKET missing')
    ca = CertificateAuthority(S3Client(bucket))

    query = json.load(sys.stdin)
    pubkey = query['pubkey']
    fqdn = query.get('fqdn')
    user = query.get('user')
    roles = query.get('roles', [])
    lifetime = int(query.get('lifetime', 90))  # lifetime in days
    renewal = int(query.get('renewal', 30))  # renew interval in days
    if renewal > lifetime:
        raise InvocationError('renewal interval must be shorter than certificate lifetime')

    sig = find_certificate(ca.get_log(), pubkey, renewal)

    if not sig:
        if fqdn:
            sig = ca.sign_host(pubkey, fqdn, f'+{lifetime}d')
        elif user:
            sig = ca.sign_user(pubkey, user, roles, f'+{lifetime}d')
        else:
            raise InvocationError('bad query')

    # terraform requires all values to be strings
    json_dump(
        dict(
            pubkey=sig['pubkey'],
            certificate=sig['certificate'],
            type=sig['type'],
            keyid=sig['keyid'],
            serial=str(sig['serial']),
            valid_after=sig['valid_after'],
            valid_before=sig['valid_before'],
            principals=','.join(sig['principals']),
        ),
        sys.stdout,
    )


class InvocationError(Exception):
    pass


def command_ssh_askpass() -> None:
    try:
        print(os.environ['SSHCA_PASSPHRASE'])
    except Exception:
        exit(1)


def _json_serialize(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f'Object of type {obj.__class__.__name__} is not JSON serializable')


def json_dump(data: Any, file: TextIO) -> None:
    json.dump(data, file, default=_json_serialize, separators=(',', ':'))


if __name__ == '__main__':
    main()
