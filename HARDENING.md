# HARDENING - OIDC / OAuth 2.0 relying-party checklist

The defensive baseline this lab implements in `secure-lab` / `demo-rp`, as a
checklist you can apply to a real deployment. Each item lists **why** and the
**PoC it defeats** (see [docs/offense.md](docs/offense.md)).

> The single most important line: **use the Authorization Code flow with PKCE,
> a confidential client, and exact redirect URIs.** Almost everything below is a
> corollary of that.

## Client / flow configuration

- [ ] **Authorization Code flow only.** Disable the **implicit** flow
      (`response_type=token`). Tokens must never travel in the URL. *(PoC 03)*
- [ ] **Disable Direct Access Grants** (ROPC / password grant). The app should
      never handle raw passwords; users authenticate on the IdP. *(PoC 01)*
- [ ] **Require PKCE (S256)** on every client, mandatory for public clients.
      Binds the code to the client that started the flow. *(PoC 02, PoC 04)*
- [ ] **Prefer confidential clients** with a strong secret kept out of source
      control; exchange the code server-side. *(PoC 02)*
- [ ] **Exact redirect URIs.** No `*`, no wildcard hosts/paths, no `http` in
      production. A loose redirect URI is account takeover. *(PoC 02)*
- [ ] **Scope `web_origins` / CORS** to known origins, not `*`.

## Tokens & sessions

- [ ] **Short access-token lifetime** (minutes) so a leaked token expires fast.
- [ ] **Validate every token:** signature (JWKS), `iss`, `aud`, `exp`, `nonce`.
- [ ] **Idle + absolute session timeouts.**
- [ ] **RP-initiated logout** that clears the local session and ends the IdP
      session.
- [ ] Store session state in **signed, httpOnly, SameSite** cookies.

## Accounts & credentials

- [ ] **Brute-force protection / lockout** at the IdP. *(PoC 01)*
- [ ] **MFA** for privileged roles.
- [ ] **No self-registration** unless explicitly required (and then with email
      verification + abuse controls).
- [ ] Enforce a real **password policy**; ban known-breached passwords.

## Transport & hostname

- [ ] **TLS everywhere** (`sslRequired = external` or `all`). This lab uses
      plain HTTP **only** because it is local.
- [ ] Set a correct, fixed **issuer hostname**; keep `iss` consistent across
      front-channel (browser) and back-channel (server) paths. See the
      issuer-mismatch note in [docs/defense.md](docs/defense.md).

## Authorization (in the app)

- [ ] **Enforce roles/permissions server-side** on every protected route; never
      trust the client. (`/admin` checks the `lab-admin` realm role.)
- [ ] Apply **least privilege** to roles and client scopes.

## Operations

- [ ] **Pin image versions** (e.g. `keycloak:26.1`), update deliberately.
- [ ] **Keep secrets out of git** (`.env`, client secrets, tokens). This repo's
      `.gitignore` excludes `.env`, `*.token`, `*.jwt`, and evidence dumps.
- [ ] **Log and monitor** auth events (failed logins, token grants, admin
      actions).

---

### How secure-lab maps to this list

`realms/secure-lab-realm.json` + `app/main.py` implement: Auth Code + PKCE S256,
confidential client, implicit & direct-grant OFF, one exact redirect URI,
brute-force protection, short token lifetimes, server-side role checks, and
proper token validation (via Authlib). The only intentional production gap is
**TLS** - omitted because the lab is local-only.
