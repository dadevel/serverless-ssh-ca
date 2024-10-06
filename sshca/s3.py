from __future__ import annotations
from contextlib import contextmanager
from typing import Generator
import time

from botocore.exceptions import ClientError
import boto3


class S3Client:
    def __init__(self, bucket: str) -> None:
        self.s3 = boto3.client('s3')
        self.bucket = bucket

    def get(self, key: str) -> bytes:
        result = self.s3.get_object(Bucket=self.bucket, Key=key)
        return result['Body'].read()

    def put(self, key: str, content: bytes, content_type: str = 'application/octet-stream', overwrite: bool = True) -> None:
        kwargs = dict(Bucket=self.bucket, Key=key, Body=content, ContentType=content_type)
        if not overwrite:
            kwargs['IfNoneMatch'] = '*'
        try:
            self.s3.put_object(**kwargs)
        except ClientError as e:
            if e.response['Error']['Code'] == 'PreconditionFailed' and e.response['Error']['Condition'] == 'If-None-Match':
                raise ObjectAlreadyExistsError(key) from e
            raise e

    def delete(self, key: str) -> None:
        self.s3.delete_object(Bucket=self.bucket, Key=key)

    @contextmanager
    def exclusive_access(self, key: str) -> Generator[S3Client, None, None]:
        try:
            self.lock(key)
            yield self
        finally:
            self.unlock(key)

    def lock(self, key: str) -> None:
        for _ in range(3):
            try:
                self.put(f'{key}.lock', b'', overwrite=False)
                return
            except Exception as e:
                print(e)
                time.sleep(2)
        raise LockContendedError(key)

    def unlock(self, key: str) -> None:
        self.delete(key=f'{key}.lock')


class ObjectAlreadyExistsError(Exception):
    pass


class LockContendedError(Exception):
    pass
