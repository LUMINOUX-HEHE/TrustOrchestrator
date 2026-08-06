#!/usr/bin/env python3
"""Trust Orchestrator REST client — stdlib only (urllib), one file.

Usage:
    from to_client import TOClient
    c = TOClient("http://localhost:8080", "admin-token")
    c.create_org("acme")
    c.issue("acme", "c1", "user", via="c0")
    print(c.state("acme"))
    c.scores("acme", "W1", score=0, bad_index=3)
    c.recover("acme", shards)          # shards: list of {"x","y","len"} dicts

Smoke check:  python3 to_client.py http://localhost:8080 <token>
"""
import json
import urllib.error
import urllib.request


class TOError(RuntimeError):
    """Gateway error: status code + {"error": ...} body."""

    def __init__(self, status, body):
        super().__init__(f"gateway: {status} {body}")
        self.status = status
        self.body = body


class TOClient:
    def __init__(self, base, token, timeout=30):
        self.base = base.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _req(self, method, path, body=None, raw=False):
        req = urllib.request.Request(self.base + path, method=method)
        req.add_header("Authorization", "Bearer " + self.token)
        data = None
        if body is not None:
            if isinstance(body, bytes):
                req.add_header("Content-Type", "application/json")
                data = body
            else:
                req.add_header("Content-Type", "application/json")
                data = json.dumps(body).encode()
        try:
            with urllib.request.urlopen(req, data=data, timeout=self.timeout) as r:
                b = r.read()
                return b if raw else (json.loads(b) if b else None)
        except urllib.error.HTTPError as e:
            raise TOError(e.code, e.read().decode(errors="replace")) from None

    # orgs (tenants)
    def orgs(self):
        return self._req("GET", "/v1/orgs")["orgs"]

    def create_org(self, name, id=None):
        return self._req("POST", "/v1/orgs", {"name": name, "id": id})

    def delete_org(self, org):
        return self._req("DELETE", "/v1/orgs/" + org)

    def org(self, org):
        return self._req("GET", "/v1/orgs/" + org)

    # trust events
    def issue(self, org, cert_id, identity, via=""):
        return self._req("POST", f"/v1/orgs/{org}/issue",
                         {"cert_id": cert_id, "identity": identity, "via": via})

    def revoke(self, org, cert_id):
        return self._req("POST", f"/v1/orgs/{org}/revoke", {"cert_id": cert_id})

    def state(self, org):
        return self._req("GET", f"/v1/orgs/{org}/state")["certs"]

    def timeline(self, org, typ="", limit=100):
        q = "?limit=%d" % limit + (f"&type={typ}" if typ else "")
        return self._req("GET", f"/v1/orgs/{org}/timeline{q}")["events"]

    # detection + recovery
    def scores(self, org, node_id, score, bad_index=None):
        ev = {"bad_index": bad_index} if bad_index is not None else None
        return self._req("POST", f"/v1/orgs/{org}/scores",
                         {"node_id": node_id, "score": score, "p_value": 0.01, "evidence": ev})

    def recover(self, org, shards):
        return self._req("POST", f"/v1/orgs/{org}/recover", {"shards": shards})

    # audit + metrics
    def audit(self, org="", typ="", identity="", cert="", limit=200):
        qs = [f"limit={limit}"]
        for k, v in (("org", org), ("type", typ), ("identity", identity), ("cert", cert)):
            if v:
                qs.append(f"{k}={urllib.parse.quote(v)}")
        return self._req("GET", "/v1/audit?" + "&".join(qs))["events"]

    def metrics(self):
        return self._req("GET", "/v1/metrics", raw=True).decode()

    # backup / restore
    def backup(self):
        return self._req("POST", "/v1/backup")

    def backup_download(self, bid):
        return self._req("GET", f"/v1/backup/{bid}/download", raw=True)

    def restore(self, bundle_bytes):
        return self._req("POST", "/v1/restore", bundle_bytes)

    # users
    def create_user(self, user_id, role, orgs=()):
        return self._req("POST", "/v1/users", {"id": user_id, "role": role, "orgs": list(orgs)})

    def users(self):
        return self._req("GET", "/v1/users")["users"]

    # webhooks
    def webhooks(self):
        return self._req("GET", "/v1/webhooks")["webhooks"]

    def create_webhook(self, url, secret="", events=()):
        return self._req("POST", "/v1/webhooks",
                         {"url": url, "secret": secret, "events": list(events)})

    def delete_webhook(self, wid):
        return self._req("DELETE", "/v1/webhooks/" + wid)


import urllib.parse  # noqa: E402  (used by audit)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        sys.exit("usage: to_client.py <base-url> <token>")
    c = TOClient(sys.argv[1], sys.argv[2])
    print("orgs:", [o["name"] for o in c.orgs()])
    print("metrics head:\n" + "\n".join(c.metrics().splitlines()[:5]))
