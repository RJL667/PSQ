"""Object-storage adapter (WS1 / SCALE-03).

Replaces the local ``scans/<domain>/…`` archive and the in-memory/disk ``_pdf_cache``
— both of which die on Render's ephemeral disk — with a pluggable store. The scan
pipeline writes a blob on completion and reads/serves it on request; keys are
``scan_id`` / content-addressed so the WS10 DR sweep can reconcile object store
against the ``scans`` table.

``LocalObjectStore`` (filesystem) is the default + dev/test impl. The S3 / Cloudflare
R2 impl swaps in behind the same tiny interface (``put``/``get``/``exists``/``url``/
``delete``/``list_prefix``) — R2 is egress-free, so prefer it in prod. **Imported by
no runtime code yet**; wiring `app.py`'s archive + PDF paths onto this is the
deploy-time step (it pairs with the Postgres cutover).
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import List, Optional


class ObjectStore:
    """Minimal blob store interface. Keys are '/'-delimited logical paths, e.g.
    ``pdfs/<scan_id>/full.pdf`` or ``archive/<domain>/<ts>.json``."""

    def put(self, key: str, data: bytes, content_type: Optional[str] = None) -> None:
        raise NotImplementedError

    def get(self, key: str) -> Optional[bytes]:
        raise NotImplementedError

    def exists(self, key: str) -> bool:
        raise NotImplementedError

    def url(self, key: str, expires_seconds: int = 3600) -> Optional[str]:
        """A URL a client can fetch the blob from (signed + expiring for S3/R2).
        Returns None if the key is absent."""
        raise NotImplementedError

    def delete(self, key: str) -> None:
        raise NotImplementedError

    def list_prefix(self, prefix: str) -> List[str]:
        """All keys under ``prefix`` — used by the DR reconciliation sweep."""
        raise NotImplementedError


def _safe_key(key: str) -> str:
    """Reject traversal / absolute keys so a key can never escape the root."""
    k = (key or "").strip().lstrip("/")
    if not k or ".." in k.split("/") or k != k.replace("\\", "/"):
        raise ValueError(f"invalid object key: {key!r}")
    return k


class LocalObjectStore(ObjectStore):
    """Filesystem-backed store under ``root``. Atomic writes (temp + replace) so a
    concurrent reader never sees a half-written blob."""

    def __init__(self, root: str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def _path(self, key: str) -> Path:
        return self.root / _safe_key(key)

    def put(self, key: str, data: bytes, content_type: Optional[str] = None) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        with self._lock:
            tmp.write_bytes(data)
            tmp.replace(path)  # atomic on the same filesystem

    def get(self, key: str) -> Optional[bytes]:
        path = self._path(key)
        try:
            return path.read_bytes()
        except FileNotFoundError:
            return None

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()

    def url(self, key: str, expires_seconds: int = 3600) -> Optional[str]:
        path = self._path(key)
        return path.resolve().as_uri() if path.is_file() else None

    def delete(self, key: str) -> None:
        try:
            self._path(key).unlink()
        except FileNotFoundError:
            pass

    def list_prefix(self, prefix: str) -> List[str]:
        base = self.root / _safe_key(prefix) if prefix else self.root
        search = base if base.is_dir() else self.root
        out = []
        for p in search.rglob("*"):
            if p.is_file() and not p.name.endswith(".tmp"):
                out.append(p.relative_to(self.root).as_posix())
        return sorted(out)


class S3ObjectStore(ObjectStore):
    """S3 / Cloudflare R2 store (boto3). R2 is egress-free — prefer it in prod.
    Configured via OBJECT_STORE_BUCKET (+ S3_ENDPOINT_URL for R2) and the standard
    AWS credential chain. ``url`` returns a presigned, expiring URL."""

    def __init__(self, bucket: str, endpoint_url: Optional[str] = None):
        import boto3  # only imported when S3 backend is selected
        self.bucket = bucket
        self._s3 = boto3.client("s3", endpoint_url=endpoint_url)

    def put(self, key, data, content_type=None):
        extra = {"ContentType": content_type} if content_type else {}
        self._s3.put_object(Bucket=self.bucket, Key=_safe_key(key), Body=data, **extra)

    def get(self, key):
        try:
            return self._s3.get_object(Bucket=self.bucket, Key=_safe_key(key))["Body"].read()
        except Exception:
            return None

    def exists(self, key):
        try:
            self._s3.head_object(Bucket=self.bucket, Key=_safe_key(key))
            return True
        except Exception:
            return False

    def url(self, key, expires_seconds=3600):
        if not self.exists(key):
            return None
        return self._s3.generate_presigned_url(
            "get_object", Params={"Bucket": self.bucket, "Key": _safe_key(key)},
            ExpiresIn=expires_seconds)

    def delete(self, key):
        try:
            self._s3.delete_object(Bucket=self.bucket, Key=_safe_key(key))
        except Exception:
            pass

    def list_prefix(self, prefix):
        out, token = [], None
        while True:
            kw = {"Bucket": self.bucket, "Prefix": _safe_key(prefix) if prefix else ""}
            if token:
                kw["ContinuationToken"] = token
            resp = self._s3.list_objects_v2(**kw)
            out += [o["Key"] for o in resp.get("Contents", [])]
            token = resp.get("NextContinuationToken")
            if not token:
                return sorted(out)


_store = None


def make_object_store() -> ObjectStore:
    """S3/R2 when OBJECT_STORE_BACKEND=s3 (+ OBJECT_STORE_BUCKET); else local fs at
    OBJECT_STORE_DIR (default ``scans/_objstore``)."""
    global _store
    if _store is not None:
        return _store
    import os
    if os.environ.get("OBJECT_STORE_BACKEND") == "s3" and os.environ.get("OBJECT_STORE_BUCKET"):
        _store = S3ObjectStore(os.environ["OBJECT_STORE_BUCKET"],
                               os.environ.get("S3_ENDPOINT_URL"))
    else:
        root = os.environ.get("OBJECT_STORE_DIR") or str(
            Path(__file__).parent / "scans" / "_objstore")
        _store = LocalObjectStore(root)
    return _store


def reset_for_tests(store=None):
    global _store
    _store = store
