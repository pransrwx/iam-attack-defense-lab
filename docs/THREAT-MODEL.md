# Threat model & MITRE ATT&CK map

A lightweight threat model for the lab's OIDC relying party, plus how the four
PoCs map to STRIDE and MITRE ATT&CK.

## System & assets

- **IdP** - Keycloak (`secure-lab`, `vuln-lab` realms) on `:8080`.
- **Relying party** - FastAPI app on `:8000`.
- **Backing store** - PostgreSQL (users, sessions, realm config).
- **Assets to protect:** user credentials, authorization codes, access/ID
  tokens, sessions, and privileged roles (`lab-admin`).

## Actors

- **Legitimate user** - authenticates via the IdP (e.g. `alice`).
- **External attacker** - can send the victim links and run a server
  (`:6660` in the PoCs). Cannot read the Docker-internal network or the DB.
- **Malicious / injected page script** - JavaScript running in the victim's
  browser context (3rd-party include or XSS), relevant to front-channel leaks.

## Trust boundaries

1. **Browser <-> IdP/app** (front channel, over the network) - attacker can
   influence URLs the victim visits and read anything placed in a URL the
   victim's browser lands on.
2. **App <-> IdP** (back channel, inside Docker) - not attacker-reachable in this
   model; this is where code->token exchange and JWKS fetches happen.
3. **Services <-> DB** - internal only.

The design principle: **secrets and token exchange live behind boundary 2;
nothing sensitive crosses boundary 1 in a URL.** The vulns in `vuln-lab` all
violate this by pushing codes/tokens through the front channel or removing the
binding that protects them.

## STRIDE x PoC x ATT&CK

| PoC | Weakness | STRIDE | ATT&CK technique |
|---|---|---|---|
| 01 Direct access grant + brute force | ROPC enabled, no lockout | Spoofing, Elevation | T1110 Brute Force; T1078 Valid Accounts |
| 02 Redirect URI hijack | wildcard redirect, public, no PKCE | Spoofing, Info Disclosure, Elevation | T1557 Adversary-in-the-Middle; T1539 Steal Token |
| 03 Implicit flow token leak | implicit flow on | Information Disclosure | T1539 Steal Token; T1550 Use Alt. Auth Material |
| 04 Missing PKCE | PKCE not enforced | Tampering, Spoofing | T1557 AiTM; T1550 Use Alt. Auth Material |

## Primary attack surface (and the control that covers it)

| Surface | Risk | Control |
|---|---|---|
| `/token` endpoint | password guessing, ROPC abuse | disable ROPC; brute-force lockout |
| `redirect_uri` handling | code/token exfiltration | exact allow-list; PKCE |
| Front-channel responses | tokens in URL | no implicit flow; back-channel exchange |
| Authorization code | interception & replay | PKCE S256; short code TTL; confidential client |
| Protected routes | privilege escalation | server-side role checks (least privilege) |

## Residual risk / out of scope

- **TLS** is intentionally omitted (local lab); in production it is mandatory and
  is itself a control against boundary-1 interception.
- Supply-chain, container escape, and host security are out of scope.
- The model assumes the back channel (boundary 2) is not attacker-reachable;
  network segmentation must enforce that in a real deployment.

## References

- OAuth 2.0 Security Best Current Practice (IETF).
- RFC 7636 - PKCE. RFC 6749/6819 - OAuth 2.0 & threat model. OpenID Connect Core.
- MITRE ATT&CK - Enterprise.
