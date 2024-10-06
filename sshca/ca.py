from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, TypedDict
import os
import re
import subprocess
import sys

from sshkey_tools.cert import SSHCertificate

from sshca.s3 import S3Client
from sshca.tmp import TempDir

BUCKET_CA_KEY = 'private/sshca.key'
BUCKET_CA_PUBKEY = 'public/sshca.pub'
BUCKET_LOG = 'private/sshca.log'
BUCKET_KRL = 'public/sshca.krl'

USER_REGEX = re.compile(r'^[a-z0-9-]{1,64}$')
ROLE_REGEX = re.compile(r'^[a-z0-9-]{1,64}$')
HOST_REGEX = re.compile(r'^[a-z0-9-.]{1,256}$')

SSH_PUBKEY_ALGORITHM = 'ed25519'
SSH_ENCRYPTION_KDF_ROUNDS = 32  # default is 16
SSH_ENCRYPTION_CIPHER = 'chacha20-poly1305@openssh.com'


class Signature(TypedDict):
    pubkey: str
    certificate: str
    type: str
    keyid: str
    serial: int
    valid_after: datetime
    valid_before: datetime
    principals: list[str]
    path: str


class CertificateAuthority:
    def __init__(self, s3: S3Client) -> None:
        self.s3 = s3

    def initialize(self, overwrite: bool = False) -> None:
        self.s3.put(BUCKET_LOG, b'', overwrite=overwrite)

        with TempDir() as tmp:
            self._ssh_keygen('-q', '-k', '-f', tmp.krl)
            self.s3.put(BUCKET_KRL, tmp.krl.read_bytes(), overwrite=overwrite)

            self._ssh_keygen('-q', '-t', SSH_PUBKEY_ALGORITHM, '-C', '', '-a', str(SSH_ENCRYPTION_KDF_ROUNDS), '-Z', SSH_ENCRYPTION_CIPHER, '-f', tmp.ca_key)
            self.s3.put(BUCKET_CA_KEY, tmp.ca_key.read_bytes(), overwrite=overwrite)
            self.s3.put(BUCKET_CA_PUBKEY, tmp.ca_pubkey.read_bytes(), overwrite=overwrite)

    @staticmethod
    def _verify_roles(roles: list[str]) -> list[str]:
        for role in roles:
            if not ROLE_REGEX.fullmatch(role):
                raise ValueError(f'role {role!r} invalid')
        return list(sorted(set(f'role:{role}' for role in roles)))

    def sign_user(self, pubkey: str, username: str, roles: list[str], validity: str) -> Signature:
        if not USER_REGEX.fullmatch(username):
            raise ValueError(f'username {username!r} invalid')
        principals = [f'user:{username}'] + self._verify_roles(roles)
        keyid = username
        return self._sign_pubkey(pubkey, principals, keyid, validity, host=False)

    def sign_host(self, pubkey: str, fqdn: str, validity: str) -> Signature:
        if not HOST_REGEX.fullmatch(fqdn):
            raise ValueError(f'hostname {fqdn!r} invalid')
        principals = [fqdn]
        keyid = fqdn
        return self._sign_pubkey(pubkey, principals, keyid, validity, host=True)

    def _sign_pubkey(self, pubkey: str, principals: list[str], keyid: str, validity: str, host: bool) -> Signature:
        options = ('-h',) if host else ()
        with TempDir() as tmp:
            tmp.id_pubkey.write_text(pubkey)
            tmp.ca_key.write_bytes(self.s3.get(BUCKET_CA_KEY))
            tmp.ca_key.chmod(0o600)

            with self.s3.exclusive_access(BUCKET_LOG):
                log = self.s3.get(BUCKET_LOG).splitlines()
                serial = len(log) + 1
                self._ssh_keygen('-s', tmp.ca_key, '-I', keyid, *options, '-n', ','.join(principals), '-V', validity, '-z', str(serial), tmp.id_pubkey)
                content = tmp.id_cert.read_bytes()
                parts = content.split(b' ', maxsplit=2)
                cert = parts[0] + b' ' + parts[1]
                log.append(cert)
                self.s3.put(BUCKET_LOG, b'\n'.join(log))

        return self._deserialize_cert(cert)

    def revoke(self, serial: int) -> None:
        if serial <= 0:
            raise ValueError('invalid serial number')

        with TempDir() as tmp:
            tmp.ca_key.write_bytes(self.s3.get(BUCKET_CA_KEY))
            tmp.ca_key.chmod(0o600)
            with self.s3.exclusive_access(BUCKET_KRL):
                tmp.krl.write_bytes(self.s3.get(BUCKET_KRL))
                self._ssh_keygen('-q', '-k', '-s', tmp.ca_key, '-f', tmp.krl, '-u', '/dev/stdin', input=f'serial:{serial}'.encode())
                self.s3.put(BUCKET_KRL, tmp.krl.read_bytes())

    def get_pubkey(self) -> bytes:
        return self.s3.get(BUCKET_CA_PUBKEY)

    @staticmethod
    def _translate_cert_type(value: int) -> str:
        match value:
            case 1:
                return 'user'
            case 2:
                return 'host'
            case _:
                return 'unknown'

    @classmethod
    def _deserialize_cert(cls, value: str|bytes) -> Signature:
        cert = SSHCertificate.from_string(value)
        return Signature(
            pubkey=cert.header.public_key.value.to_string().rstrip(),
            certificate=cert.to_string().rstrip(),
            type=cls._translate_cert_type(cert.fields.cert_type.value),
            keyid=cert.fields.key_id.value,
            serial=cert.fields.serial.value,
            # sshkey-tools converts the timestamp to local timezone, but does not embed tzinfo, so we have to convert them back to utc
            valid_after=datetime.fromtimestamp(cert.fields.valid_after.value.timestamp(), timezone.utc),
            valid_before=datetime.fromtimestamp(cert.fields.valid_before.value.timestamp(), timezone.utc),
            principals=cert.fields.principals.value,
            path='',
        )

    def get_log(self) -> Generator[Signature, None, None]:
        for line in self.s3.get(BUCKET_LOG).splitlines():
            yield self._deserialize_cert(line)

    def get_krl(self) -> bytes:
        return self.s3.get(BUCKET_KRL)

    def _ssh_keygen(self, *args: str|Path, input: bytes|None = None) -> None:
        command = ['ssh-keygen', *args]
        if os.isatty(sys.stdin.fileno()):
            env = None
        else:
            env = dict(os.environ, SSH_ASKPASS=sys.argv[0], SSH_ASKPASS_REQUIRE='force')
        process = subprocess.run(command, env=env, check=True, text=False, input=input, capture_output=True)
        if process.returncode != 0:
            raise SubprocessError(process.stderr.decode())


class SubprocessError(Exception):
    pass
