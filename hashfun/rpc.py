"""Minimal JSON-RPC client for Bitcoin Core-compatible nodes (bitcoind, hashfund)."""
import base64
import http.client
import json
import os
from urllib.parse import urlparse


class RPCError(Exception):
    def __init__(self, error):
        super().__init__(f"{error.get('code')}: {error.get('message')}")
        self.code = error.get("code")
        self.message = error.get("message")


class RPC:
    """RPC("http://user:pass@127.0.0.1:18443") or RPC(url, cookie_file=...).
    Optional wallet: RPC(url).wallet("name")."""

    def __init__(self, url: str, cookie_file: str = None, timeout: float = 60, wallet: str = None):
        u = urlparse(url)
        self.host, self.port = u.hostname, u.port
        self.timeout = timeout
        self.base_path = u.path or "/"
        self.wallet_name = wallet
        if u.username:
            auth = f"{u.username}:{u.password or ''}"
        elif cookie_file:
            with open(os.path.expanduser(cookie_file)) as f:
                auth = f.read().strip()
        else:
            auth = None
        self.auth = "Basic " + base64.b64encode(auth.encode()).decode() if auth else None
        self.url = url
        self._id = 0

    def wallet(self, name: str) -> "RPC":
        r = RPC.__new__(RPC)
        r.__dict__.update(self.__dict__)
        r.wallet_name = name
        return r

    def call(self, method, *params):
        self._id += 1
        body = json.dumps({"jsonrpc": "1.0", "id": self._id, "method": method, "params": list(params)})
        path = self.base_path if not self.wallet_name else f"/wallet/{self.wallet_name}"
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        headers = {"Content-Type": "application/json"}
        if self.auth:
            headers["Authorization"] = self.auth
        try:
            conn.request("POST", path, body, headers)
            resp = conn.getresponse()
            data = resp.read()
        finally:
            conn.close()
        if resp.status == 401:
            raise RPCError({"code": -401, "message": "unauthorized"})
        out = json.loads(data)
        if out.get("error"):
            raise RPCError(out["error"])
        return out["result"]

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *a: self.call(name, *a)
