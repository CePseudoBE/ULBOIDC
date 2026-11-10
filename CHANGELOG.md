# Changelog

## 3.0.0

Full rewrite on top of Ally's `Oauth2Driver` (redirect, state, PKCE) and
`openid-client` 6 (discovery, code exchange, ID token validation, userinfo,
refresh, logout).

### Breaking changes

- Node.js 24+, `@adonisjs/ally` 6.1+ (PKCE support) and `@adonisjs/core` 7 are required.
- Config: `serverUrl` is replaced by `issuer` (full URL, defaults to
  `https://auth.ulb.be/oidc`). Endpoints come from the discovery document;
  `authorizeUrl`, `accessTokenUrl` and `userInfoUrl` are removed.
- The authorization request now sends PKCE S256 (`code_challenge`) and a
  `nonce`, stored in two new encrypted cookies next to the state cookie.
- The ID token is now required and validated (JWKS signature, RS256 only,
  `iss`, `aud`, `exp`, `nonce`). The userinfo `sub` must match the ID token `sub`.
- `UlbOidcAccessToken` is replaced by `UlbOidcToken`
  (`token`, `type`, `refreshToken?`, `expiresIn?`, `expiresAt?`, `idToken?`).
  `type` is the server `token_type`, lowercased.
- `user()`: no more `'unknown'` fallbacks. `email` is `null` when absent,
  `nickName` is `preferred_username` (or `sub`), a userinfo without `sub` is an error.
- `accessToken()`, `user()` and `userFromToken()` no longer accept a request callback.
- Server and validation errors are raised as `UlbOidcError`
  (`error`, `errorDescription`, `status`) instead of generic errors.
- The `qs` dependency is replaced by `openid-client`.

### Added

- `acrValues` option: sent as `acr_values` and enforced on the ID token `acr` claim.
- `scopes` option.
- `refreshAccessToken(refreshToken)`.
- `logoutUrl({ idTokenHint?, postLogoutRedirectUri? })`.
- Discovery cached per issuer and client, with a timeout and a
  `discovery_failed` error when the issuer is unreachable.
- Unit and integration test suites (Japa), ESLint flat config, CI workflow.
