"""Reference mirror implementations used as the fixtures for the probe suite.

Two servers:

``CompliantMirror``
    A content-addressed, replay-only artifact mirror with no code-execution
    path. Intended to satisfy predicates P1-P6.

``CachingProxy``
    A conventional package-registry caching proxy of the class described in the
    July 2026 incident: resolves by name, fetches upstream on a cache miss,
    passes arbitrary paths through, and offers an on-demand build endpoint.
    Intended as the non-compliant control.

Neither server reaches the real network. ``CachingProxy`` models its upstream as
an in-process dictionary so the suite runs air-gapped.
"""

from __future__ import annotations

import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

# --------------------------------------------------------------------------
# Snapshot fixture
# --------------------------------------------------------------------------

# Artifacts pinned into the evaluation snapshot.
SNAPSHOT_BYTES: dict[tuple[str, str], bytes] = {
    ("requests", "2.31.0"): b"PK\x03\x04 requests-2.31.0 payload",
    ("numpy", "1.26.4"): b"PK\x03\x04 numpy-1.26.4 payload",
}

# Present upstream but deliberately absent from the snapshot. Used by P2.
UPSTREAM_ONLY_BYTES: dict[tuple[str, str], bytes] = {
    ("leftpad", "0.0.1"): b"PK\x03\x04 leftpad-0.0.1 payload",
}

SNAPSHOT_ID = "eval-snapshot-2026-09-13"


def digest_of(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def build_manifest() -> dict:
    artifacts = {
        f"{name}=={version}": {
            "digest": digest_of(payload),
            "size": len(payload),
        }
        for (name, version), payload in sorted(SNAPSHOT_BYTES.items())
    }
    canonical = json.dumps(artifacts, sort_keys=True, separators=(",", ":")).encode()
    return {
        "snapshot_id": SNAPSHOT_ID,
        "manifest_digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "artifacts": artifacts,
    }


def recompute_manifest_digest(artifacts: dict) -> str:
    canonical = json.dumps(artifacts, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


# --------------------------------------------------------------------------
# Shared handler plumbing
# --------------------------------------------------------------------------


class _BaseHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # silence per-request stderr noise
        return

    def _send(
        self, status: int, body: bytes, content_type: str = "application/octet-stream", **headers
    ):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in headers.items():
            self.send_header(key.replace("_", "-"), value)
        self.end_headers()
        self.wfile.write(body)

    def _reject(self, status: int, reason: str):
        self._send(status, json.dumps({"error": reason}).encode(), "application/json")


# --------------------------------------------------------------------------
# Compliant mirror
# --------------------------------------------------------------------------


class CompliantHandler(_BaseHandler):
    """Serves bytes only, addressed by name + version + digest, from a fixed snapshot."""

    def do_GET(self):
        split = urlsplit(self.path)
        if split.netloc:
            # Absolute-form request target: an upstream URL smuggled into the path.
            return self._reject(400, "path_outside_namespace")

        path = split.path
        if ".." in path:
            return self._reject(400, "path_outside_namespace")

        if path == "/manifest":
            return self._send(200, json.dumps(build_manifest()).encode(), "application/json")

        if not path.startswith("/a/"):
            return self._reject(400, "path_outside_namespace")

        parts = [p for p in path[len("/a/") :].split("/") if p != ""]
        if len(parts) == 2:
            # Name and version with no digest supplied: not resolvable here.
            return self._reject(400, "digest_required")
        if len(parts) != 3:
            return self._reject(400, "path_outside_namespace")

        name, version, supplied = parts
        payload = SNAPSHOT_BYTES.get((name, version))
        if payload is None:
            # Replay-only: absent from the snapshot is absent, full stop.
            return self._reject(404, "not_in_snapshot")
        if digest_of(payload) != supplied:
            return self._reject(409, "digest_mismatch")

        return self._send(200, payload, content_digest=digest_of(payload))

    def do_HEAD(self):
        self.do_GET()

    def _no(self):
        return self._reject(405, "method_not_allowed")

    do_POST = do_PUT = do_DELETE = do_PATCH = _no


# --------------------------------------------------------------------------
# Non-compliant caching proxy
# --------------------------------------------------------------------------


class CachingProxyHandler(_BaseHandler):
    """A conventional caching proxy. Resolves by name, fetches on miss, builds on demand."""

    def do_GET(self):
        split = urlsplit(self.path)

        # Absolute-form target: proxy it. This is the passthrough behaviour.
        if split.netloc:
            return self._send(200, b"upstream passthrough response")

        path = split.path

        if path.startswith("/proxy"):
            return self._send(200, b"upstream passthrough response")

        if path.startswith("/build/"):
            # On-demand source build. Executes artifact-supplied build metadata.
            return self._send(200, b"built wheel from sdist build metadata")

        if not path.startswith("/a/"):
            # Permissive: unknown paths are forwarded rather than refused.
            return self._send(200, b"upstream passthrough response")

        parts = [p for p in path[len("/a/") :].split("/") if p != ""]
        if len(parts) < 2:
            return self._reject(404, "not_found")

        name, version = parts[0], parts[1]

        payload = SNAPSHOT_BYTES.get((name, version))
        if payload is not None:
            return self._send(200, payload)

        payload = UPSTREAM_ONLY_BYTES.get((name, version))
        if payload is not None:
            # Cache miss resolved against upstream.
            return self._send(200, payload, x_cache="MISS")

        return self._reject(404, "not_found")

    def do_HEAD(self):
        self.do_GET()

    def _no(self):
        # Most caching proxies expose GET/HEAD only on the read path.
        return self._reject(405, "method_not_allowed")

    do_POST = do_PUT = do_DELETE = do_PATCH = _no


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------


class MirrorServer:
    def __init__(self, handler_cls, port: int = 0):
        self._httpd = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "MirrorServer":
        self._thread.start()
        return self

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join(timeout=5)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


def serve_compliant(port: int = 0) -> MirrorServer:
    return MirrorServer(CompliantHandler, port)


def serve_caching_proxy(port: int = 0) -> MirrorServer:
    return MirrorServer(CachingProxyHandler, port)
