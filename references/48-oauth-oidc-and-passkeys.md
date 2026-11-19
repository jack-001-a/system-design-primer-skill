# OAuth 2.1, OpenID Connect, and Passkeys

## Protocol roles
OAuth is an authorization framework; OpenID Connect adds an identity layer. Distinguish the authorization server, resource server, client, subject, and relying party. Use Authorization Code with PKCE for interactive public clients; do not embed client secrets in mobile or browser applications. Avoid implicit and resource-owner-password flows. Verify current standards and provider-specific behavior before deployment.

## Token validation and lifecycle
Validate signature using trusted issuer metadata and rotating keys, issuer, audience, expiry, not-before, authorized party where applicable, and allowed algorithms. Access tokens should be audience-restricted and short-lived according to risk. Define refresh-token rotation, reuse detection, revocation, session termination, and key rollover. Do not treat an ID token as an API access token.

## Redirects and browser security
Use exact registered redirect URIs, state binding, nonce for OIDC authentication, PKCE, and strict callback handling. Protect cookies with Secure, HttpOnly, and appropriate SameSite attributes. Defend against open redirects, login CSRF, token leakage through URLs, and unsafe post-logout redirects.

## Passkeys and WebAuthn
Passkeys use public-key credentials scoped to a relying party. Verify challenge freshness and one-time use, origin, RP ID, user presence/verification policy, credential ownership, and signature counter behavior according to authenticator capabilities. Design recovery, device replacement, account linking, and phishing-resistant step-up flows; passkeys do not eliminate account-recovery risk.

## Review checklist
- [ ] OAuth and OIDC responsibilities are separated correctly.
- [ ] PKCE, state, nonce, exact redirect URI, issuer and audience checks are enforced.
- [ ] Refresh rotation, revocation, and key rotation are tested.
- [ ] Passkey registration, assertion, origin, challenge, and recovery flows are tested.
- [ ] Tokens and authentication codes never enter logs, analytics, or referrers.
