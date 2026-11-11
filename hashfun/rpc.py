"""Minimal JSON-RPC client for Bitcoin Core-compatible nodes (bitcoind, hashfund)."""
import base64
import http.client
import json
import os
import threading
from urllib.parse import urlparse

# Calls that only read. They go over one kept connection per thread, and are sent again once when
# that connection turns out to have been closed by the node while it sat idle. Everything else (a
# payment, a block, a setting) gets a connection of its own and is never sent twice: a broken
# answer to one of those leaves the outcome unknown, and that is for the caller to find out.
#
# Why keep a connection at all: a new one per call leaves its source port unusable for a while
# after it closes. A tool that polls a node makes thousands a minute. On macOS that runs the
# machine out of ports (the calls then fail with "Can't assign requested address"); on Linux a
# node that starts next cannot listen on any port one of them just used.
_READ_ONLY = ("get", "list", "decode", "validate", "estimate", "help", "uptime", "testmempoolaccept", "deriveaddresses")
_STALE = (http.client.RemoteDisconnected, http.client.CannotSendRequest, http.client.ResponseNotReady,
          BrokenPipeError, ConnectionResetError, ConnectionAbortedError)


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
        self._kept = threading.local()  # .conn: this thread's kept connection (shared with wallet() views)

    def wallet(self, name: str) -> "RPC":
        r = RPC.__new__(RPC)
        r.__dict__.update(self.__dict__)
        r.wallet_name = name
        return r

    def _once(self, conn, path, body, headers):
        conn.request("POST", path, body, headers)
        resp = conn.getresponse()
        return resp.status, resp.read()

    def close(self):
        """Close this thread's kept connection, if there is one."""
        conn = getattr(self._kept, "conn", None)
        self._kept.conn = None
        if conn is not None:
            conn.close()

    def call(self, method, *params):
        self._id += 1
        body = json.dumps({"jsonrpc": "1.0", "id": self._id, "method": method, "params": list(params)})
        path = self.base_path if not self.wallet_name else f"/wallet/{self.wallet_name}"
        headers = {"Content-Type": "application/json"}
        if self.auth:
            headers["Authorization"] = self.auth
        if not method.startswith(_READ_ONLY):
            conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            try:
                status, data = self._once(conn, path, body, headers)
            finally:
                conn.close()
        else:
            conn = getattr(self._kept, "conn", None)
            fresh = conn is None
            if fresh:
                conn = self._kept.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            try:
                try:
                    status, data = self._once(conn, path, body, headers)
                except _STALE:
                    if fresh:
                        raise
                    # the node closed it while it sat idle (it does after 30 s): once more on a new one
                    conn.close()
                    conn = self._kept.conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
                    status, data = self._once(conn, path, body, headers)
            except BaseException:
                self.close()  # whatever state it is in, it is not one to send the next call on
                raise
        if status == 401:
            raise RPCError({"code": -401, "message": "unauthorized"})
        out = json.loads(data)
        if out.get("error"):
            raise RPCError(out["error"])
        return out["result"]

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *a: self.call(name, *a)
