from argparse import ArgumentParser, Namespace, HelpFormatter
from tempfile import TemporaryDirectory
from pathlib import Path
import shutil
import re
import sys
import subprocess
import time

from botocore.exceptions import ClientError
import boto3

BUCKET_CA_KEY = 'private/sshca.key'
BUCKET_CA_PUBKEY = 'public/sshca.pub'
BUCKET_LOG = 'private/sshca.log'
BUCKET_KRL = 'public/sshca.krl'
LOCAL_CA_KEY = 'key'
LOCAL_CA_PUBKEY = 'key.pub'
LOCAL_ID_PUBKEY = 'id.pub'
LOCAL_ID_CERT = 'id-cert.pub'
LOCAL_KRL = 'sshca.krl'
USER_REGEX = re.compile(r'^[a-z0-9-]{1,64}$')
ROLE_REGEX = re.compile(r'^[a-z0-9-]{1,64}$')
HOST_REGEX = re.compile(r'^[a-z0-9-.]{1,256}$')
SSH_PUBKEY_ALGORITHM = 'ed25519'
SSH_ENCRYPTION_KDF_ROUNDS = 32  # default is 16
SSH_ENCRYPTION_CIPHER = 'chacha20-poly1305@openssh.com'


def main() -> None:
    formatter = lambda prog: HelpFormatter(prog, max_help_position=round(shutil.get_terminal_size().columns))
    entrypoint = ArgumentParser(formatter_class=formatter)
    entrypoint.add_argument('--debug', action='store_const', const=True, default=False)

    parsers = entrypoint.add_subparsers(dest='command', required=True)

    parser = parsers.add_parser('init')
    parser.add_argument('-b', '--bucket', required=True)
    parser.add_argument('--force', action='store_const', default=False, const=True)

    parser = parsers.add_parser('sign', epilog="note: TIMESPEC format is described under 'validity_interval' in ssh-keygen manpage")
    parser.add_argument('-b', '--bucket', required=True, metavar='BUCKET')
    parser.add_argument('-k', '--pubkey', required=True, metavar='BLOB|FILE')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--user', metavar='USERNAME')
    group.add_argument('-f', '--host', metavar='HOSTFQDN')
    parser.add_argument('-r', '--role', action='append', default=[], metavar='ROLENAME')
    parser.add_argument('-v', '--validity', default='+30d', metavar='TIMESPEC')

    parser = parsers.add_parser('revoke')
    parser.add_argument('-b', '--bucket', required=True)
    parser.add_argument('-s', '--serial', type=int, metavar='NUMBER')

    parser = parsers.add_parser('get-pubkey')
    parser.add_argument('-b', '--bucket', required=True)

    parser = parsers.add_parser('get-log')
    parser.add_argument('-b', '--bucket', required=True)
    parser.add_argument('-r', '--raw', action='store_const', const=True, default=False)

    parser = parsers.add_parser('get-krl')
    parser.add_argument('-b', '--bucket', required=True)
    parser.add_argument('-r', '--raw', action='store_const', const=True, default=False)

    opts = entrypoint.parse_args()
    function = globals()[f'command_{opts.command.replace('-', '_')}']
    try:
        with TemporaryDirectory(prefix='sshca-') as tmpdir:
            opts.tmpdir = Path(tmpdir)
            opts.local_ca_key = opts.tmpdir/LOCAL_CA_KEY
            opts.local_ca_pubkey = opts.tmpdir/LOCAL_CA_PUBKEY
            opts.local_id_pubkey = opts.tmpdir/LOCAL_ID_PUBKEY
            opts.local_id_cert = opts.tmpdir/LOCAL_ID_CERT
            opts.local_krl = opts.tmpdir/LOCAL_KRL
            opts.local_krl = opts.tmpdir/LOCAL_KRL
            function(opts)
    except Exception as e:
        if opts.debug:
            raise
        print(f'{e.__class__.__name__}: {e}')
        exit(1)


def command_init(opts: Namespace) -> None:
    s3 = S3Client(opts.bucket)

    s3.put_object(BUCKET_LOG, b'', overwrite=opts.force)

    subprocess.run(['ssh-keygen', '-q', '-k', '-f', opts.local_krl])
    s3.put_object(BUCKET_KRL, opts.local_krl.read_bytes(), overwrite=opts.force)

    subprocess.run(['ssh-keygen', '-q', '-t', SSH_PUBKEY_ALGORITHM, '-C', '', '-a', str(SSH_ENCRYPTION_KDF_ROUNDS), '-Z', SSH_ENCRYPTION_CIPHER, '-f', opts.local_ca_key], check=True)
    s3.put_object(BUCKET_CA_KEY, opts.local_ca_key.read_bytes(), overwrite=opts.force)
    s3.put_object(BUCKET_CA_PUBKEY, opts.local_ca_pubkey.read_bytes(), overwrite=opts.force)


def command_sign(opts: Namespace) -> None:
    for role in opts.role:
        if not ROLE_REGEX.fullmatch(role):
            raise ValueError(f'role {role!r} invalid')
    roles = list(sorted(set(f'role:{role}' for role in opts.role)))

    if opts.user:
        if not USER_REGEX.fullmatch(opts.user):
            raise ValueError(f'username {opts.user!r} invalid')
        principals = [f'user:{opts.user}'] + roles
        keyid = opts.user
        options = []
    elif opts.host:
        if not HOST_REGEX.fullmatch(opts.host):
            raise ValueError(f'hostname {opts.host!r} invalid')
        principals = [opts.host] + roles
        keyid = opts.host
        options = ['-h']
    else:
        raise RuntimeError('unreachable')

    sign_pubkey(opts, opts.pubkey, principals, keyid, options, opts.validity)


def sign_pubkey(opts: Namespace, pubkey: str, principals: list[str], keyid: str, options: list[str], validity: str) -> None:
    pubkey_path = Path(pubkey)
    if pubkey_path.is_file():
        opts.local_id_pubkey = pubkey_path
    elif pubkey.startswith('ssh-'):
        opts.local_id_pubkey.write_text(pubkey)
    else:
        raise ValueError(f'pubkey {pubkey!r} invalid')

    s3 = S3Client(opts.bucket)
    opts.local_ca_key.write_bytes(s3.get_object(BUCKET_CA_KEY))
    opts.local_ca_key.chmod(0o600)

    s3.lock_object(BUCKET_LOG)
    try:
        log = s3.get_object(BUCKET_LOG).splitlines()
        serial = len(log) + 1
        subprocess.run(['ssh-keygen', '-s', opts.local_ca_key, '-I', keyid, *options, '-n', ','.join(principals), '-V', validity, '-z', str(serial), opts.local_id_pubkey], check=True)
        if pubkey_path.is_file():
            content = pubkey_path.with_name(pubkey_path.name.removesuffix('.pub') + '-cert.pub').read_bytes()
        else:
            content = opts.local_id_cert.read_bytes()
        parts = content.split(b' ', maxsplit=2)
        cert = parts[0] + b' ' + parts[1]
        log.append(cert)
        s3.put_object(BUCKET_LOG, b'\n'.join(log))
    finally:
        s3.unlock_object(BUCKET_LOG)

    if opts.local_id_pubkey != pubkey_path:
        print(cert.decode())


def command_revoke(opts: Namespace) -> None:
    assert opts.serial > 0

    s3 = S3Client(opts.bucket)
    opts.local_ca_key.write_bytes(s3.get_object(BUCKET_CA_KEY))
    opts.local_ca_key.chmod(0o600)
    s3.lock_object(BUCKET_KRL)
    try:
        opts.local_krl.write_bytes(s3.get_object(BUCKET_KRL))
        subprocess.run(['ssh-keygen', '-q', '-k', '-s', opts.local_ca_key, '-f', opts.local_krl, '-u', '/dev/stdin'], input=f'serial:{opts.serial}'.encode(), check=True)
        s3.put_object(BUCKET_KRL, opts.local_krl.read_bytes())
    finally:
        s3.unlock_object(BUCKET_KRL)


def command_get_pubkey(opts: Namespace) -> None:
    s3 = S3Client(opts.bucket)
    content = s3.get_object(BUCKET_CA_PUBKEY)
    sys.stdout.buffer.write(content)


def command_get_log(opts: Namespace) -> None:
    s3 = S3Client(opts.bucket)
    content = s3.get_object(BUCKET_LOG)
    if opts.raw:
        sys.stdout.buffer.write(content)
    else:
        subprocess.run(['ssh-keygen', '-L', '-f', '/dev/stdin'], input=content)


def command_get_krl(opts: Namespace) -> None:
    s3 = S3Client(opts.bucket)
    content = s3.get_object(BUCKET_KRL)
    if opts.raw:
        sys.stdout.buffer.write(content)
    else:
        subprocess.run(['ssh-keygen', '-Q', '-l', '-f', '/dev/stdin'], input=content)


class S3Client:
    def __init__(self, bucket: str) -> None:
        self.s3 = boto3.client('s3')
        self.bucket = bucket

    def get_object(self, key: str) -> bytes:
        result = self.s3.get_object(Bucket=self.bucket, Key=key)
        return result['Body'].read()

    def put_object(self, key: str, content: bytes, content_type: str = 'application/octet-stream', overwrite: bool = True) -> None:
        kwargs = dict(Bucket=self.bucket, Key=key, Body=content, ContentType=content_type)
        if not overwrite:
            kwargs['IfNoneMatch'] = '*'
        try:
            self.s3.put_object(**kwargs)
        except ClientError as e:
            if e.response['Error']['Code'] == 'PreconditionFailed' and e.response['Error']['Condition'] == 'If-None-Match':
                raise ObjectAlreadyExistsError(key) from e
            raise e

    def delete_object(self, key: str) -> None:
        self.s3.delete_object(Bucket=self.bucket, Key=key)

    def lock_object(self, key: str) -> None:
        for _ in range(3):
            try:
                self.put_object(f'{key}.lock', b'', overwrite=False)
                return
            except Exception as e:
                print(e)
                time.sleep(2)
        raise LockContendedError(key)

    def unlock_object(self, key: str) -> None:
        self.delete_object(key=f'{key}.lock')


class ObjectAlreadyExistsError(Exception):
    pass


class LockContendedError(Exception):
    pass


if __name__ == '__main__':
    main()
