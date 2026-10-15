"""
Demo OpenID Connect relying party for the secure-lab realm.

Authorization Code flow with PKCE (S256), confidential client:
  /login          start login (redirect to Keycloak)
  /auth/callback  exchange the code for tokens, validate the ID token, open a session
  /me             protected: show the signed-in user
  /admin          protected and role-gated: requires the lab-admin role
  /logout         clear the local session and log out at Keycloak

The issuer-mismatch handling (two URLs for one Keycloak) is explained in
docs/defense.md.
"""
import base64
import json
import os

import httpx
from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

# PUBLIC   = what the browser reaches (and what the token `iss` claim says).
# INTERNAL = what this app reaches over the Docker network (server-to-server).
ISSUER_INTERNAL = os.getenv("OIDC_ISSUER_INTERNAL", "http://keycloak:8080/realms/secure-lab")
ISSUER_PUBLIC = os.getenv("OIDC_ISSUER_PUBLIC", "http://localhost:8080/realms/secure-lab")
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000")
CLIENT_ID = os.getenv("OIDC_CLIENT_ID", "demo-rp")
CLIENT_SECRET = os.getenv("OIDC_CLIENT_SECRET", "demo-rp-secret-CHANGE-ME")
APP_SECRET = os.getenv("APP_SECRET", "lab-session-secret-change-me")

app = FastAPI(title="Demo Relying Party")
app.add_middleware(SessionMiddleware, secret_key=APP_SECRET, same_site="lax")

oauth = OAuth()
oauth.register(
    name="keycloak",
    server_metadata_url=f"{ISSUER_INTERNAL}/.well-known/openid-configuration",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    client_kwargs={"scope": "openid profile email", "code_challenge_method": "S256"},
)


def _decode_jwt_payload(token: str) -> dict:
    """Base64url-decode a JWT payload for display only (no verification)."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))
    except Exception:
        return {}


def _roles_from_session(request: Request) -> list[str]:
    claims = _decode_jwt_payload(request.session.get("access_token", ""))
    return claims.get("realm_access", {}).get("roles", [])


def _page(body: str) -> str:
    return f"""
    <html><head><title>Demo Relying Party</title>
    <style>
      body{{font-family:system-ui,sans-serif;max-width:680px;margin:3rem auto;padding:0 1rem;line-height:1.5}}
      code,pre{{background:#f0f0f0;padding:2px 6px;border-radius:4px}}
      pre{{padding:1rem;overflow:auto}}
      .ok{{color:#1a7f37}} .tag{{color:#888;font-size:.85rem}} .err{{color:#b00}}
      a.btn{{display:inline-block;background:#0969da;color:#fff;padding:.5rem 1rem;border-radius:6px;text-decoration:none;margin-right:.5rem}}
    </style></head><body>{body}</body></html>
    """


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/idp-check")
async def idp_check():
    url = f"{ISSUER_INTERNAL}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(url)
        if r.status_code == 200:
            return {"reachable": True, "issuer": r.json().get("issuer")}
        return JSONResponse(status_code=200, content={"reachable": True, "note": f"realm not imported? (HTTP {r.status_code})"})
    except Exception as e:
        return JSONResponse(status_code=503, content={"reachable": False, "error": str(e)})


@app.get("/login")
async def login(request: Request):
    return await oauth.keycloak.authorize_redirect(request, f"{APP_BASE_URL}/auth/callback")


@app.get("/auth/callback")
async def callback(request: Request):
    try:
        token = await oauth.keycloak.authorize_access_token(request)
    except Exception as e:
        return HTMLResponse(_page(f"<h1 class='err'>Login failed</h1><pre>{e}</pre><a href='/'>home</a>"), status_code=400)
    userinfo = token.get("userinfo") or {}
    request.session["user"] = dict(userinfo)
    request.session["access_token"] = token.get("access_token", "")
    request.session["id_token"] = token.get("id_token", "")
    return RedirectResponse("/me")


@app.get("/logout")
async def logout(request: Request):
    id_token = request.session.get("id_token", "")
    request.session.clear()
    end_session = (
        f"{ISSUER_PUBLIC}/protocol/openid-connect/logout"
        f"?post_logout_redirect_uri={APP_BASE_URL}/&id_token_hint={id_token}"
    )
    return RedirectResponse(end_session)


@app.get("/me", response_class=HTMLResponse)
async def me(request: Request):
    user = request.session.get("user")
    if not user:
        return RedirectResponse("/login")
    roles = _roles_from_session(request)
    return _page(
        f"<h1>Signed in</h1>"
        f"<p class='ok'>Authenticated via Keycloak (Authorization Code + PKCE).</p>"
        f"<p><b>{user.get('name','?')}</b> &lt;{user.get('email','?')}&gt;<br>"
        f"<span class='tag'>sub: {user.get('sub','?')}</span></p>"
        f"<p>Realm roles: <code>{', '.join(roles) or '(none)'}</code></p>"
        f"<p><a class='btn' href='/admin'>Try /admin</a>"
        f"<a class='btn' href='/logout'>Logout</a></p>"
        f"<details><summary>ID token claims</summary><pre>{json.dumps(user, indent=2)}</pre></details>"
    )


@app.get("/admin", response_class=HTMLResponse)
async def admin(request: Request):
    if not request.session.get("user"):
        return RedirectResponse("/login")
    roles = _roles_from_session(request)
    if "lab-admin" not in roles:
        return HTMLResponse(
            _page(
                "<h1 class='err'>403 - Forbidden</h1>"
                "<p>This route requires the <code>lab-admin</code> role.</p>"
                f"<p class='tag'>Your roles: {', '.join(roles) or '(none)'}</p>"
                "<p><a href='/me'>back</a></p>"
            ),
            status_code=403,
        )
    return _page(
        "<h1 class='ok'>Admin area</h1>"
        "<p>You hold <code>lab-admin</code>. This is a role-gated route.</p>"
        "<p><a href='/me'>back</a></p>"
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    signed_in = bool(request.session.get("user"))
    cta = (
        "<a class='btn' href='/me'>My profile</a><a class='btn' href='/logout'>Logout</a>"
        if signed_in else
        "<a class='btn' href='/login'>Login with Keycloak</a>"
    )
    return _page(
        f"<h1>Demo Relying Party</h1>"
        f"<p class='ok'>Running.</p>"
        f"<p>OpenID Connect login (Authorization Code + PKCE) against the "
        f"<code>secure-lab</code> realm.</p>"
        f"<p>{cta}</p>"
        f"<ul><li><a href='/healthz'>/healthz</a></li>"
        f"<li><a href='/idp-check'>/idp-check</a></li></ul>"
        f"<p class='tag'>Public issuer: <code>{ISSUER_PUBLIC}</code></p>"
    )
