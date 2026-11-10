# ulboidc-ally

AdonisJS Ally driver for the ULB OpenID Connect server (Apereo CAS).

Ally handles the redirect, the `state` cookie, PKCE (S256) and the callback
checks. [openid-client](https://github.com/panva/openid-client) handles the
protocol: discovery, code exchange, ID token validation (JWKS signature, RS256
only, `iss`, `aud`, `exp`, `nonce`, `acr`), userinfo, refresh and logout.

## Requirements

- Node.js 24+
- AdonisJS 7 (`@adonisjs/core` 7)
- `@adonisjs/ally` 6.1+ (first version with PKCE support)

## Installation

```bash
npm i github:CePseudoBE/ULBOIDC
```

## Configuration

`config/ally.ts`:

```ts
import env from '#start/env'
import { defineConfig } from '@adonisjs/ally'
import { ulbOidcService } from 'ulboidc-ally'

const allyConfig = defineConfig({
  ulb: ulbOidcService({
    clientId: env.get('ULB_OIDC_CLIENT_ID'),
    clientSecret: env.get('ULB_OIDC_CLIENT_SECRET'),
    callbackUrl: env.get('ULB_OIDC_CALLBACK_URL'),
    issuer: env.get('ULB_OIDC_ISSUER'),
    acrValues: 'mfa-nextauth',
  }),
})

export default allyConfig
```

| Option         | Required | Default                              | Description                                                                 |
| -------------- | -------- | ------------------------------------ | --------------------------------------------------------------------------- |
| `clientId`     | yes      |                                      | OIDC client id                                                              |
| `clientSecret` | yes      |                                      | OIDC client secret                                                          |
| `callbackUrl`  | yes      |                                      | Redirect URI registered for the client                                      |
| `issuer`       | no       | `https://auth.ulb.be/oidc`           | Use `https://auth-dev.ulb.be/oidc` for the dev server (VPN required)        |
| `scopes`       | no       | `openid profile email eduperson`     | Requested scopes                                                            |
| `acrValues`    | no       |                                      | Sent as `acr_values` (e.g. `mfa-nextauth`) and enforced on the ID token `acr` |

Endpoints come from the issuer discovery document
(`<issuer>/.well-known/openid-configuration`). It is loaded once per issuer and
client, with a 10 s timeout; an unreachable issuer raises a `UlbOidcError` with
`error === 'discovery_failed'`.

## Usage

### Login

```ts
router.get('/auth/login', ({ ally }) => ally.use('ulb').redirect())
```

### Callback

```ts
import { UlbOidcError } from 'ulboidc-ally'

router.get('/auth/callback', async ({ ally, session, response }) => {
  const ulb = ally.use('ulb')

  if (ulb.accessDenied()) return response.forbidden('Login cancelled')
  if (ulb.stateMisMatch()) return response.badRequest('Login expired, please retry')
  if (ulb.hasError()) return response.badRequest(ulb.getError())

  try {
    const user = await ulb.user()
    session.put('ulb', {
      sub: user.id,
      refreshToken: user.token.refreshToken,
      idToken: user.token.idToken,
    })
    return response.redirect('/')
  } catch (error) {
    if (error instanceof UlbOidcError && error.error === 'acr_mismatch') {
      return response.forbidden('MFA is required')
    }
    throw error
  }
})
```

`user()` returns:

| Field      | Source                                                                     |
| ---------- | -------------------------------------------------------------------------- |
| `id`       | `sub` (must match the ID token `sub`)                                      |
| `name`     | `name`, else `given_name family_name`                                      |
| `nickName` | `preferred_username`, else `sub`                                           |
| `email`    | `email` or `null`                                                          |
| `original` | Full userinfo response (`given_name`, `family_name`, `eduPersonAffiliation`…) |
| `token`    | `{ token, type, refreshToken?, expiresIn?, expiresAt?, idToken? }`         |

`accessToken()` and `user()` share the same code exchange: calling both does not
redeem the code twice.

### User from an access token

```ts
const user = await ally.use('ulb').userFromToken(accessToken)
```

### Refresh

```ts
const token = await ally.use('ulb').refreshAccessToken(refreshToken)
```

### Logout

```ts
router.get('/auth/logout', async ({ ally, session, response }) => {
  const url = await ally.use('ulb').logoutUrl({
    idTokenHint: session.get('ulb')?.idToken,
    postLogoutRedirectUri: 'http://localhost:3333/',
  })
  session.forget('ulb')
  return response.redirect(url)
})
```

### Errors

Every failure of the OIDC server or of a validation is a `UlbOidcError`:

- `error`: the server `error` (`invalid_grant`, `expired_accessToken`…) or a
  local code (`discovery_failed`, `acr_mismatch`, `OAUTH_JWT_CLAIM_COMPARISON_FAILED`…);
- `errorDescription`: the server `error_description` (or CAS `message`);
- `status`: the HTTP status of the server response when there is one.

A wrong or missing `state` raises Ally's `E_OAUTH_STATE_MISMATCH`, a callback
without `code` raises Ally's `E_OAUTH_MISSING_CODE`.

## Development

```bash
npm install
npm run lint
npm run typecheck
npm run build
npm test
```

`build/` is committed because the package is installed from GitHub: run
`npm run build` and commit the result with every source change.

### Tests

- `npm test`: unit tests, no network (HTTP mocked with undici `MockAgent`, ID
  tokens signed with test RSA keys generated by `jose`).
- `npm run test:integration`: tests against `auth-dev.ulb.be` (ULB VPN required).
- `npm run test:all`: both.

Integration tests read `.env.test` (not committed):

```bash
cp .env.test.example .env.test
```

```
ULB_OIDC_TEST_ISSUER=https://auth-dev.ulb.be/oidc
ULB_OIDC_TEST_CLIENT_ID=wildcard_oidc
ULB_OIDC_TEST_CLIENT_SECRET=any-string
ULB_OIDC_TEST_CALLBACK_URL=http://localhost:3333/auth/callback
```

When the variables are missing or the dev discovery document is unreachable
(no VPN), the integration tests are skipped with an explicit message instead of
failing.

### Manual end-to-end test

The full login (human credentials + MFA) cannot be automated. To validate login,
refresh and logout against `auth-dev.ulb.be`:

1. Connect to the ULB VPN.
2. Create a demo app and install the driver from your working copy:

   ```bash
   npm init adonisjs@latest ulb-demo -- --kit=web
   cd ulb-demo
   node ace add @adonisjs/ally
   npm i ../ULBOIDC
   ```

3. Configure `config/ally.ts` as above with `issuer: 'https://auth-dev.ulb.be/oidc'`,
   `clientId: 'wildcard_oidc'`, any `clientSecret`,
   `callbackUrl: 'http://localhost:3333/auth/callback'` and
   `acrValues: 'mfa-nextauth'`.
4. Add the login, callback and logout routes above, plus:

   ```ts
   router.get('/', ({ session }) => session.get('ulb') ?? 'Logged out')

   router.get('/auth/refresh', async ({ ally, session }) => {
     const token = await ally.use('ulb').refreshAccessToken(session.get('ulb').refreshToken)
     session.put('ulb', { ...session.get('ulb'), refreshToken: token.refreshToken ?? session.get('ulb').refreshToken })
     return token
   })
   ```

5. `node ace serve --hmr`, then check:
   - `/auth/login` shows the ULB login page, asks for MFA, then `/` shows your `sub`;
   - `/auth/refresh` returns a new access token;
   - `/auth/logout` ends the CAS session: `/auth/login` asks for credentials again.

## License

MIT
