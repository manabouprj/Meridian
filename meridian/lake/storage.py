"""Object storage behind the lake and the landing zone: local folder, Amazon S3 or Azure Blob / ADLS Gen2.

Roots:
  data/lake                                                  local folder (development, small sites)
  s3://bucket/prefix                                         Amazon S3 (IAM role / instance credentials)
  abfss://container@account.dfs.core.windows.net/prefix      Azure Data Lake Storage Gen2 (managed identity)
Credentials come from the platform identity (IAM role, managed identity) - never from config.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, Protocol


class ObjectStore(Protocol):
    root: str

    def put(self, key: str, data: bytes) -> None: ...
    def get(self, key: str) -> bytes: ...
    def list(self, prefix: str = "") -> Iterator[str]: ...
    def delete(self, key: str) -> None: ...
    def uri(self, key: str = "") -> str: ...


class LocalStore:
    def __init__(self, root: str):
        self.root = str(Path(root))
        Path(self.root).mkdir(parents=True, exist_ok=True)

    def _p(self, key: str) -> Path:
        p = (Path(self.root) / key).resolve()
        if Path(self.root).resolve() not in p.parents and p != Path(self.root).resolve():
            raise ValueError("key escapes the store root")
        return p

    def put(self, key: str, data: bytes) -> None:
        p = self._p(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, p)                       # atomic: readers never see half a file

    def get(self, key: str) -> bytes:
        return self._p(key).read_bytes()

    def list(self, prefix: str = "") -> Iterator[str]:
        base = Path(self.root)
        start = base / prefix if prefix else base
        if not start.exists():
            return iter(())
        files = [start] if start.is_file() else sorted(x for x in start.rglob("*") if x.is_file() and not x.name.endswith(".tmp"))
        return (str(f.relative_to(base)).replace(os.sep, "/") for f in files)

    def delete(self, key: str) -> None:
        self._p(key).unlink(missing_ok=True)

    def uri(self, key: str = "") -> str:
        return str(Path(self.root) / key) if key else self.root


class S3Store:
    def __init__(self, root: str, client=None):
        import boto3
        self.root = root.rstrip("/")
        rest = self.root[len("s3://"):]
        self.bucket, _, self.prefix = rest.partition("/")
        self.s3 = client or boto3.client("s3")

    def _k(self, key: str) -> str:
        return f"{self.prefix}/{key}".lstrip("/") if self.prefix else key

    def put(self, key: str, data: bytes) -> None:
        # No SSE header on purpose: the bucket default (SSE-KMS with the MERIDIAN customer-managed key + bucket key)
        # applies. Sending ServerSideEncryption="aws:kms" without a key id would select the AWS-managed aws/s3 key.
        self.s3.put_object(Bucket=self.bucket, Key=self._k(key), Body=data)

    def get(self, key: str) -> bytes:
        return self.s3.get_object(Bucket=self.bucket, Key=self._k(key))["Body"].read()

    def list(self, prefix: str = "") -> Iterator[str]:
        pag = self.s3.get_paginator("list_objects_v2")
        strip = len(self.prefix) + 1 if self.prefix else 0
        for page in pag.paginate(Bucket=self.bucket, Prefix=self._k(prefix)):
            for o in page.get("Contents", []):
                yield o["Key"][strip:]

    def delete(self, key: str) -> None:
        self.s3.delete_object(Bucket=self.bucket, Key=self._k(key))

    def uri(self, key: str = "") -> str:
        return f"s3://{self.bucket}/{self._k(key)}" if key else self.root


class AzureStore:
    """ADLS Gen2 / Blob through the Blob API (works with hierarchical namespace accounts)."""

    def __init__(self, root: str, service=None):
        self.root = root.rstrip("/")
        rest = self.root.split("://", 1)[1]
        container_account, _, self.prefix = rest.partition("/")
        self.container, _, host = container_account.partition("@")
        self.account = host.split(".")[0]
        if service is None:
            from azure.identity import DefaultAzureCredential
            from azure.storage.blob import BlobServiceClient
            service = BlobServiceClient(f"https://{self.account}.blob.core.windows.net", credential=DefaultAzureCredential())
        self.cc = service.get_container_client(self.container)

    def _k(self, key: str) -> str:
        return f"{self.prefix}/{key}".lstrip("/") if self.prefix else key

    def put(self, key: str, data: bytes) -> None:
        # immutability (WORM) policies forbid overwrites; batches are idempotent, so an existing blob is final
        from azure.core.exceptions import ResourceExistsError
        try:
            self.cc.upload_blob(self._k(key), data, overwrite=False)
        except ResourceExistsError:
            pass

    def get(self, key: str) -> bytes:
        return self.cc.download_blob(self._k(key)).readall()

    def list(self, prefix: str = "") -> Iterator[str]:
        strip = len(self.prefix) + 1 if self.prefix else 0
        for b in self.cc.list_blobs(name_starts_with=self._k(prefix)):
            yield b.name[strip:]

    def delete(self, key: str) -> None:
        self.cc.delete_blob(self._k(key))

    def uri(self, key: str = "") -> str:
        return f"{self.root}/{key}" if key else self.root


def open_store(root: str) -> ObjectStore:
    if root.startswith("s3://"):
        return S3Store(root)
    if root.startswith(("abfss://", "az://", "abfs://")):
        return AzureStore(root)
    return LocalStore(root)
