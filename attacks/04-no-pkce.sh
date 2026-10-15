#!/usr/bin/env bash
#
# PKCE enforcement check. vuln-rp accepts an auth request with no code_challenge,
# so the code is not bound to the client that started the flow and an intercepted
# code (see 02-redirect-uri-hijack.py) is freely redeemable. secure-lab's demo-rp
# requires PKCE S256 and rejects requests without a challenge.
# PKCE (RFC 7636): pick a random verifier, send BASE64URL(SHA256(verifier)) as the
# challenge, prove possession with the raw verifier at the token exchange.
# Lab only.
set -euo pipefail
KC="${KC:-http://localhost:8080}"
bold() { printf '\033[1m%s\033[0m\n' "$1"; }
auth() { echo "$KC/realms/$1/protocol/openid-connect/auth"; }

# 1) vuln-lab: no code_challenge is fine
bold "[1] vuln-lab - start Authorization Code flow WITHOUT PKCE"
code="$(curl -s -o /dev/null -w '%{http_code}' \
  "$(auth vuln-lab)?client_id=vuln-rp&response_type=code&scope=openid&redirect_uri=http://localhost:6660/callback&state=x")"
echo "  -> HTTP $code  (200 = accepted; the code will have NO PKCE binding)"
echo

# 2) secure-lab: PKCE required
bold "[2] secure-lab - same request WITHOUT PKCE"
loc="$(curl -s -D - -o /dev/null \
  "$(auth secure-lab)?client_id=demo-rp&response_type=code&scope=openid&redirect_uri=http://localhost:8000/auth/callback&state=x" \
  | grep -i '^location:' || true)"
# Pull the error_description out of the redirect for readability.
echo "  -> $(python3 - "$loc" <<'PY'
import sys, urllib.parse
loc = sys.argv[1].split(' ',1)[1].strip() if ' ' in sys.argv[1] else sys.argv[1]
q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
print("REFUSED:", q.get("error",[""])[0], "-", q.get("error_description",[""])[0])
PY
)"
echo

# 3) secure-lab done RIGHT: with a proper S256 challenge it proceeds
bold "[3] secure-lab - same request WITH a valid PKCE S256 challenge"
read -r VERIFIER CHALLENGE < <(python3 - <<'PY'
import os, base64, hashlib
v = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
c = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b'=').decode()
print(v, c)
PY
)
code2="$(curl -s -o /dev/null -w '%{http_code}' \
  "$(auth secure-lab)?client_id=demo-rp&response_type=code&scope=openid&redirect_uri=http://localhost:8000/auth/callback&state=x&code_challenge=${CHALLENGE}&code_challenge_method=S256")"
echo "  -> HTTP $code2  (200 = accepted; code is now bound to verifier ${VERIFIER:0:12}...)"
echo
bold "Takeaway: PKCE binds the code to the client that started the flow."
echo "Without it (vuln-lab), an intercepted code (see PoC 02) is freely redeemable."
echo "Fix: require PKCE (S256) on every public client."
