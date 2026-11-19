# OAuth 2.1, OpenID Connect, and Passkeys

## Protocol roles
OAuth is an authorization framework; OpenID Connect adds an identity layer. Distinguish the authorization server, resource server, client, subject, and relying party. Use Authorization Code with PKCE for interactive public clients; do not embed client secrets in mobile or browser applications. Avoid implicit and resource-owner-password flows. Verify current standards and provider-specific behavior before deployment.

## Token validation and lifecycle
First determine whether the access token is a JWT or opaque token; validate JWTs locally only under the issuer contract, and use the provider-supported introspection path for opaque tokens. For JWTs, pin an allowed algorithm set from trusted configuration (never accept an algorithm selected solely by the token), resolve keys only from trusted issuer metadata/JWKS, handle key rotation and unknown `kid` safely, and validate signature, exact issuer, intended audience, expiry, not-before, and `azp` when required by the OIDC profile. For ID tokens, also validate the authentication request binding (`nonce` when sent) and the applicable audience/authorized-party rules. Under OpenID Connect Core, `aud` must include this relying party's `client_id`; when multiple audiences are present, the client should verify `azp`, and if `azp` is present it must identify this client. Do not make `azp` a universal mandatory claim for every single-audience ID token unless the applicable profile or provider contract requires it. Apply the exact rules from the [OpenID Connect Core ID Token specification](https://openid.net/specs/openid-connect-core-1_0.html). Access tokens should be audience-restricted and short-lived according to risk. Define refresh-token rotation, reuse detection, revocation, session termination, and key rollover. Do not treat an ID token as an API access token or assume every access token is a JWT.

## Redirects and browser security
Use exact registered redirect URIs, state binding, nonce for OIDC authentication, PKCE with `S256` for public clients, and strict callback handling. Bind the authorization response to the initiating browser session; validate `state` even when PKCE is used, and validate `nonce` when an OIDC authentication request included one. Protect cookies with Secure, HttpOnly, and appropriate SameSite attributes. Defend against open redirects, login CSRF, token leakage through URLs, and unsafe post-logout redirects.

## Passkeys and WebAuthn
Passkeys use public-key credentials scoped to a relying party. Verify challenge freshness and one-time use, exact expected origin, RP ID hash, user presence/verification policy, credential ownership, and signature counter behavior according to authenticator capabilities. Do not treat a non-increasing signature counter as a universal clone detector: synced passkeys and authenticators differ, so apply the WebAuthn guidance for the authenticator model and use risk signals rather than rejecting every zero or unchanged counter. Design recovery, device replacement, account linking, and phishing-resistant step-up flows; passkeys do not eliminate account-recovery risk.

## Review checklist
- [ ] OAuth and OIDC responsibilities are separated correctly.
- [ ] PKCE, state, nonce, exact redirect URI, issuer and audience checks are enforced.
- [ ] Refresh rotation, revocation, and key rotation are tested.
- [ ] Passkey registration, assertion, origin, challenge, and recovery flows are tested.
- [ ] Tokens and authentication codes never enter logs, analytics, or referrers.
