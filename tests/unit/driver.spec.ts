import { createHash } from 'node:crypto'
import { test } from '@japa/runner'
import { errors } from '@adonisjs/ally'
import { SignJWT, exportJWK, generateKeyPair, type JWTPayload } from 'jose'
import type { Group } from '@japa/runner/core'
import { MockAgent, getGlobalDispatcher, setGlobalDispatcher } from 'undici'
import { UlbOidcDriver, UlbOidcError, type UlbOidcConfig } from '../../index.js'
import { callbackDriver, catchError, createContext, startLogin } from '../helpers.js'

const ORIGIN = 'https://auth.test'
const ISSUER = `${ORIGIN}/oidc`
const config: UlbOidcConfig = {
  issuer: ISSUER,
  clientId: 'my-client',
  clientSecret: 'my-secret',
  callbackUrl: 'http://localhost:3333/auth/callback',
}

const agent = new MockAgent()
agent.disableNetConnect()

// Restored after each group so the integration suite keeps real network access in test:all.
function useMockAgent(group: Group) {
  group.setup(() => {
    const previous = getGlobalDispatcher()
    setGlobalDispatcher(agent)
    return () => setGlobalDispatcher(previous)
  })
}

const signingKey = await generateKeyPair('RS256')
const otherKey = await generateKeyPair('RS256')
const jwk = { ...(await exportJWK(signingKey.publicKey)), kid: 'cas', alg: 'RS256', use: 'sig' }

function metadata(issuer: string) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/oidcAuthorize`,
    token_endpoint: `${issuer}/oidcAccessToken`,
    userinfo_endpoint: `${issuer}/oidcProfile`,
    end_session_endpoint: `${issuer}/oidcLogout`,
    jwks_uri: `${issuer}/jwks`,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    code_challenge_methods_supported: ['S256'],
  }
}

const json = { headers: { 'content-type': 'application/json' } }
const auth = agent.get(ORIGIN)
auth
  .intercept({ path: '/oidc/.well-known/openid-configuration' })
  .reply(200, metadata(ISSUER), json)
  .persist()
auth
  .intercept({ path: '/oidc/jwks' })
  .reply(200, { keys: [jwk] }, json)
  .persist()

function signIdToken(claims: JWTPayload, key = signingKey.privateKey) {
  const now = Math.floor(Date.now() / 1000)
  return new SignJWT({
    iss: ISSUER,
    aud: config.clientId,
    sub: 'jdoe',
    iat: now,
    exp: now + 300,
    ...claims,
  })
    .setProtectedHeader({ alg: 'RS256', kid: 'cas' })
    .sign(key)
}

function unsignedIdToken(claims: JWTPayload) {
  const now = Math.floor(Date.now() / 1000)
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url')
  const payload = {
    iss: ISSUER,
    aud: config.clientId,
    sub: 'jdoe',
    iat: now,
    exp: now + 300,
    ...claims,
  }
  return `${encode({ alg: 'none' })}.${encode(payload)}.`
}

function mockTokenEndpoint(reply: { status?: number; body: object }) {
  const sent: { body?: URLSearchParams } = {}
  auth
    .intercept({
      path: '/oidc/oidcAccessToken',
      method: 'POST',
      body: (body) => {
        sent.body = new URLSearchParams(body)
        return true
      },
    })
    .reply(reply.status ?? 200, reply.body, json)
  return sent
}

function mockUserInfo(body: object, status = 200) {
  auth.intercept({ path: '/oidc/oidcProfile' }).reply(status, body, json)
}

/**
 * Goes through redirect + callback and mocks the token endpoint with an ID
 * token built from the nonce sent in the authorization request.
 */
async function loginWith(
  idToken: (nonce: string) => Promise<string> | string,
  driverConfig: UlbOidcConfig = config
) {
  const { url, cookies } = await startLogin(driverConfig)
  const nonce = url.searchParams.get('nonce')!
  const sent = mockTokenEndpoint({
    body: {
      access_token: 'access-token',
      token_type: 'Bearer',
      refresh_token: 'refresh-token',
      expires_in: 3600,
      id_token: await idToken(nonce),
    },
  })
  const driver = callbackDriver(
    driverConfig,
    { code: 'the-code', state: url.searchParams.get('state')! },
    cookies
  )
  return { driver, sent, url }
}

const invalidIdTokens: Record<string, (nonce: string) => Promise<string> | string> = {
  'a bad signature': (nonce) => signIdToken({ nonce }, otherKey.privateKey),
  'a wrong audience': (nonce) => signIdToken({ nonce, aud: 'other-client' }),
  'an expired exp': (nonce) =>
    signIdToken({
      nonce,
      iat: Math.floor(Date.now() / 1000) - 7200,
      exp: Math.floor(Date.now() / 1000) - 3600,
    }),
  'a different nonce': () => signIdToken({ nonce: 'another-nonce' }),
  'alg none': (nonce) => unsignedIdToken({ nonce }),
  'alg HS256': (nonce) =>
    new SignJWT({ iss: ISSUER, aud: config.clientId, sub: 'jdoe', nonce })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(new TextEncoder().encode(config.clientSecret.padEnd(32, '!'))),
}

test.group('UlbOidcDriver | redirect', (group) => {
  useMockAgent(group)

  test('builds the authorization URL with PKCE, state and nonce', async ({ assert }) => {
    const { url, cookies } = await startLogin(config)

    assert.equal(url.origin + url.pathname, `${ISSUER}/oidcAuthorize`)
    assert.equal(url.searchParams.get('client_id'), config.clientId)
    assert.equal(url.searchParams.get('redirect_uri'), config.callbackUrl)
    assert.equal(url.searchParams.get('response_type'), 'code')
    assert.equal(url.searchParams.get('scope'), 'openid profile email eduperson')
    assert.isNotEmpty(url.searchParams.get('state'))
    assert.isNotEmpty(url.searchParams.get('nonce'))
    assert.isNotEmpty(url.searchParams.get('code_challenge'))
    assert.equal(url.searchParams.get('code_challenge_method'), 'S256')
    assert.isFalse(url.searchParams.has('acr_values'))
    assert.properties(cookies, [
      'ulb_oidc_oauth_state',
      'ulb_oidc_oauth_code_verifier',
      'ulb_oidc_oauth_nonce',
    ])
  })

  test('sends acr_values when configured', async ({ assert }) => {
    const { url } = await startLogin({ ...config, acrValues: 'mfa-nextauth' })
    assert.equal(url.searchParams.get('acr_values'), 'mfa-nextauth')
  })
})

test.group('UlbOidcDriver | callback', (group) => {
  useMockAgent(group)

  test('rejects the state "{$self}"')
    .with(['wrong-state', ''])
    .run(async ({ assert }, state) => {
      const { cookies } = await startLogin(config)
      const query: Record<string, string> = { code: 'the-code' }
      if (state) query.state = state

      const error = await catchError(callbackDriver(config, query, cookies).accessToken())
      assert.instanceOf(error, errors.E_OAUTH_STATE_MISMATCH)
    })

  test('reports access_denied', ({ assert }) => {
    const driver = callbackDriver(config, { error: 'access_denied' })
    assert.isTrue(driver.accessDenied())
    assert.isTrue(driver.hasError())
  })

  test('exchanges the code with the PKCE verifier', async ({ assert }) => {
    const { driver, sent, url } = await loginWith((nonce) => signIdToken({ nonce }))
    const token = await driver.accessToken()

    const verifier = sent.body!.get('code_verifier')!
    const challenge = createHash('sha256').update(verifier).digest('base64url')
    assert.equal(challenge, url.searchParams.get('code_challenge'))
    assert.equal(sent.body!.get('grant_type'), 'authorization_code')
    assert.equal(sent.body!.get('code'), 'the-code')
    assert.equal(sent.body!.get('redirect_uri'), config.callbackUrl)

    assert.equal(token.token, 'access-token')
    assert.equal(token.refreshToken, 'refresh-token')
    assert.equal(token.expiresIn, 3600)
    assert.instanceOf(token.expiresAt, Date)
    assert.isString(token.idToken)
  })

  test('maps the userinfo without exchanging the code twice', async ({ assert }) => {
    const { driver } = await loginWith((nonce) => signIdToken({ nonce }))
    mockUserInfo({
      sub: 'jdoe',
      name: 'John Doe',
      given_name: 'John',
      family_name: 'Doe',
      email: 'john.doe@ulb.be',
      preferred_username: 'jdoe',
      eduPersonAffiliation: ['member', 'staff'],
    })

    const token = await driver.accessToken()
    const user = await driver.user()

    assert.equal(user.token, token)
    assert.equal(user.id, 'jdoe')
    assert.equal(user.name, 'John Doe')
    assert.equal(user.nickName, 'jdoe')
    assert.equal(user.email, 'john.doe@ulb.be')
    assert.deepEqual(user.original.eduPersonAffiliation, ['member', 'staff'])
  })

  test('surfaces the OAuth error of the token endpoint', async ({ assert }) => {
    const { url, cookies } = await startLogin(config)
    mockTokenEndpoint({
      status: 400,
      body: { error: 'invalid_grant', error_description: 'Code expired' },
    })
    const driver = callbackDriver(
      config,
      { code: 'the-code', state: url.searchParams.get('state')! },
      cookies
    )

    const error = await catchError(driver.accessToken())
    assert.instanceOf(error, UlbOidcError)
    assert.equal(error.error, 'invalid_grant')
    assert.equal(error.errorDescription, 'Code expired')
    assert.equal(error.status, 400)
  })

  test('surfaces a non OAuth error body of the token endpoint', async ({ assert }) => {
    const { url, cookies } = await startLogin(config)
    mockTokenEndpoint({
      status: 500,
      body: { status: 500, error: 'Internal Server Error', message: 'INVALID_TICKET' },
    })
    const driver = callbackDriver(
      config,
      { code: 'the-code', state: url.searchParams.get('state')! },
      cookies
    )

    const error = await catchError(driver.accessToken())
    assert.instanceOf(error, UlbOidcError)
    assert.equal(error.error, 'Internal Server Error')
    assert.equal(error.errorDescription, 'INVALID_TICKET')
    assert.equal(error.status, 500)
  })

  test('rejects a userinfo without sub', async ({ assert }) => {
    const { driver } = await loginWith((nonce) => signIdToken({ nonce }))
    mockUserInfo({ name: 'John Doe' })
    assert.instanceOf(await catchError(driver.user()), UlbOidcError)
  })

  test('rejects a userinfo whose sub differs from the ID token', async ({ assert }) => {
    const { driver } = await loginWith((nonce) => signIdToken({ nonce }))
    mockUserInfo({ sub: 'someone-else' })
    assert.instanceOf(await catchError(driver.user()), UlbOidcError)
  })
})

test.group('UlbOidcDriver | ID token validation', (group) => {
  useMockAgent(group)

  test('rejects an ID token with {$self}')
    .with(Object.keys(invalidIdTokens))
    .run(async ({ assert }, invalid) => {
      const { driver } = await loginWith(invalidIdTokens[invalid])
      assert.instanceOf(await catchError(driver.accessToken()), UlbOidcError)
    })

  test('accepts the expected acr', async ({ assert }) => {
    const mfaConfig = { ...config, acrValues: 'mfa-nextauth' }
    const { driver } = await loginWith(
      (nonce) => signIdToken({ nonce, acr: 'mfa-nextauth' }),
      mfaConfig
    )
    const token = await driver.accessToken()
    assert.equal(token.token, 'access-token')
  })

  test('rejects an acr different from acrValues', async ({ assert }) => {
    const mfaConfig = { ...config, acrValues: 'mfa-nextauth' }
    const { driver } = await loginWith(
      (nonce) => signIdToken({ nonce, acr: 'mfa-simple' }),
      mfaConfig
    )
    const error = await catchError(driver.accessToken())
    assert.instanceOf(error, UlbOidcError)
    assert.equal(error.error, 'acr_mismatch')
  })
})

test.group('UlbOidcDriver | tokens and logout', (group) => {
  useMockAgent(group)

  test('refreshes the access token', async ({ assert }) => {
    const sent = mockTokenEndpoint({
      body: {
        access_token: 'new-token',
        token_type: 'Bearer',
        refresh_token: 'new-refresh',
        expires_in: 600,
      },
    })
    const driver = new UlbOidcDriver(createContext('/'), config)
    const token = await driver.refreshAccessToken('old-refresh')

    assert.equal(sent.body!.get('grant_type'), 'refresh_token')
    assert.equal(sent.body!.get('refresh_token'), 'old-refresh')
    assert.equal(token.token, 'new-token')
    assert.equal(token.refreshToken, 'new-refresh')
    assert.equal(token.expiresIn, 600)
    assert.instanceOf(token.expiresAt, Date)
  })

  test('surfaces the OAuth error of a refresh', async ({ assert }) => {
    mockTokenEndpoint({ status: 400, body: { error: 'invalid_grant' } })
    const driver = new UlbOidcDriver(createContext('/'), config)
    const error = await catchError(driver.refreshAccessToken('bad'))
    assert.instanceOf(error, UlbOidcError)
    assert.equal(error.error, 'invalid_grant')
  })

  test('fetches the user from an access token', async ({ assert }) => {
    mockUserInfo({ sub: 'jdoe', given_name: 'John', family_name: 'Doe' })
    const user = await new UlbOidcDriver(createContext('/'), config).userFromToken('access-token')
    assert.equal(user.id, 'jdoe')
    assert.equal(user.name, 'John Doe')
    assert.deepEqual(user.token, { token: 'access-token', type: 'bearer' })
  })

  test('surfaces the userinfo error of an invalid access token', async ({ assert }) => {
    auth.intercept({ path: '/oidc/oidcProfile' }).reply(401, '', {
      headers: { 'www-authenticate': 'Bearer error="invalid_token", error_description="Expired"' },
    })
    const error = await catchError(
      new UlbOidcDriver(createContext('/'), config).userFromToken('bad')
    )
    assert.instanceOf(error, UlbOidcError)
    assert.equal(error.error, 'invalid_token')
    assert.equal(error.status, 401)
  })

  test('surfaces a userinfo error sent without WWW-Authenticate', async ({ assert }) => {
    mockUserInfo({ error: 'expired_accessToken', error_description: 'Unauthorized' }, 401)
    const error = await catchError(
      new UlbOidcDriver(createContext('/'), config).userFromToken('bad')
    )
    assert.instanceOf(error, UlbOidcError)
    assert.equal(error.error, 'expired_accessToken')
    assert.equal(error.errorDescription, 'Unauthorized')
    assert.equal(error.status, 401)
  })

  test('builds the logout URL', async ({ assert }) => {
    const driver = new UlbOidcDriver(createContext('/'), config)
    const url = new URL(
      await driver.logoutUrl({
        idTokenHint: 'id-token',
        postLogoutRedirectUri: 'http://localhost:3333/',
      })
    )
    assert.equal(url.origin + url.pathname, `${ISSUER}/oidcLogout`)
    assert.equal(url.searchParams.get('id_token_hint'), 'id-token')
    assert.equal(url.searchParams.get('post_logout_redirect_uri'), 'http://localhost:3333/')
  })
})

test.group('UlbOidcDriver | discovery', (group) => {
  useMockAgent(group)

  test('caches the discovery per issuer', async ({ assert }) => {
    const issuer = 'https://cache.test/oidc'
    let calls = 0
    agent
      .get('https://cache.test')
      .intercept({ path: '/oidc/.well-known/openid-configuration' })
      .reply(() => {
        calls++
        return { statusCode: 200, data: metadata(issuer), responseOptions: json }
      })
      .persist()

    const cachedConfig = { ...config, issuer }
    await new UlbOidcDriver(createContext('/'), cachedConfig).logoutUrl()
    await new UlbOidcDriver(createContext('/'), cachedConfig).logoutUrl()
    assert.equal(calls, 1)
  })

  test('fails clearly when the issuer is unreachable', async ({ assert }) => {
    agent
      .get('https://down.test')
      .intercept({ path: '/oidc/.well-known/openid-configuration' })
      .replyWithError(new Error('connect ECONNREFUSED'))

    const error = await catchError(
      new UlbOidcDriver(createContext('/'), {
        ...config,
        issuer: 'https://down.test/oidc',
      }).redirectUrl()
    )
    assert.instanceOf(error, UlbOidcError)
    assert.equal(error.error, 'discovery_failed')
    assert.include(error.message, 'https://down.test/oidc')
  })
})
