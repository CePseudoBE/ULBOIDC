# ulboidc-ally

AdonisJS Ally driver for ULB OpenID Connect authentication.

## Requirements

- AdonisJS v7+
- `@adonisjs/ally` v6+
- Node.js 24+

## Installation

```bash
npm i github:CePseudoBE/ULBOIDC
```

## Configuration

Register the driver in your `config/ally.ts` :

```typescript
import { defineConfig } from '@adonisjs/ally'
import { ulbOidcService } from 'ulboidc-ally'

const allyConfig = defineConfig({
  ulb: ulbOidcService({
    clientId: env.get('ULB_OIDC_CLIENT_ID'),
    clientSecret: env.get('ULB_OIDC_CLIENT_SECRET'),
    callbackUrl: env.get('ULB_OIDC_CALLBACK_URL'),
    serverUrl: env.get('ULB_OIDC_SERVER_URL'),
  }),
})

export default allyConfig
```

Add these variables to your `.env` :

```
ULB_OIDC_CLIENT_ID=your_client_id
ULB_OIDC_CLIENT_SECRET=your_client_secret
ULB_OIDC_CALLBACK_URL=http://localhost:3333/auth/callback
ULB_OIDC_SERVER_URL=your_server_url
```

### Options

| Option | Required | Description |
|---|---|---|
| `clientId` | Yes | OAuth2 client ID |
| `clientSecret` | Yes | OAuth2 client secret |
| `callbackUrl` | Yes | Redirect URI after authentication |
| `serverUrl` | Yes | ULB OIDC server hostname |
| `authorizeUrl` | No | Custom authorize endpoint |
| `accessTokenUrl` | No | Custom token endpoint |
| `userInfoUrl` | No | Custom userinfo endpoint |

## Usage

### Redirect to ULB login

```typescript
router.get('/auth/login', async ({ ally }) => {
  return ally.use('ulb').redirect()
})
```

### Handle callback

```typescript
router.get('/auth/callback', async ({ ally, auth, response }) => {
  const ulb = ally.use('ulb')

  if (ulb.accessDenied()) {
    return response.forbidden('Access denied')
  }

  if (ulb.hasError()) {
    return response.badRequest(ulb.getError())
  }

  const ulbUser = await ulb.user()

  // ulbUser contains: id, name, nickName, email, original (raw OIDC claims), token
})
```

### Get user from existing token

```typescript
const user = await ally.use('ulb').userFromToken(accessToken)
```

## Scopes

The driver requests these scopes by default: `openid`, `profile`, `email`, `eduperson`.

## License

MIT
