from __future__ import annotations
from pathlib import Path
from tempfile import TemporaryDirectory

TEMP_PREFIX = 'sshca-'
LOCAL_CA_KEY = 'key'
LOCAL_CA_PUBKEY = 'key.pub'
LOCAL_ID_PUBKEY = 'id.pub'
LOCAL_ID_CERT = 'id-cert.pub'
LOCAL_KRL = 'sshca.krl'


class TempDir:
    def __enter__(self) -> TempDir:
        self.dir = TemporaryDirectory(prefix=TEMP_PREFIX)
        base = Path(self.dir.name)
        self.ca_key = base/LOCAL_CA_KEY
        self.ca_pubkey = base/LOCAL_CA_PUBKEY
        self.id_pubkey = base/LOCAL_ID_PUBKEY
        self.id_cert = base/LOCAL_ID_CERT
        self.krl = base/LOCAL_KRL
        return self

    def __exit__(self, type, value, traceback) -> None:
        self.dir.cleanup()
