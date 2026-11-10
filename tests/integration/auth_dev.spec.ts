import { existsSync } from 'node:fs'
import { test } from '@japa/runner'
import type { JWK } from 'jose'
import type { ServerMetadata } from 'openid-client'
import { UlbOidcDriver, UlbOidcError, type UlbOidcConfig } from '../../index.js'
import { callbackDriver, catchError, createContext, startLogin } from '../helpers.js'

if (existsSync('.env.test')) process.loadEnvFile('.env.test')

const env = process.env
const issuer = env.ULB_OIDC_TEST_ISSUER ?? ''
const config: UlbOidcConfig = {
  issuer,
  clientId: env.ULB_OIDC_TEST_CLIENT_ID ?? '',
  clientSecret: env.ULB_OIDC_TEST_CLIENT_SECRET ?? '',
  callbackUrl: env.ULB_OIDC_TEST_CALLBACK_URL ?? '',
}
const discoveryUrl = `${issuer}/.well-known/openid-configuration`

async function findSkipReason(): Promise<string | undefined> {
  if (Object.values(config).some((value) => !value)) {
    return 'ULB_OIDC_TEST_* variables missing: copy .env.test.example to .env.test'
  }
  try {
    const response = await fetch(discoveryUrl, { signal: AbortSignal.timeout(5000) })
    if (!response.ok) return `${discoveryUrl} answered HTTP ${response.status}`
  } catch {
    return `${discoveryUrl} is unreachable (ULB VPN connected?)`
  }
}

async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url)
  return (await response.json()) as T
}

const skipReason = await findSkipReason()
if (skipReason) console.warn(`Skipping ULB OIDC integration tests: ${skipReason}`)

test.group('auth-dev.ulb.be', (group) => {
  group.tap((t) => t.skip(Boolean(skipReason), skipReason))

  test('serves the expected discovery document', async ({ assert }) => {
    const metadata = await fetchJson<ServerMetadata>(discoveryUrl)

    assert.equal(metadata.issuer, issuer)
    for (const endpoint of [
      'authorization_endpoint',
      'token_endpoint',
      'userinfo_endpoint',
      'end_session_endpoint',
      'jwks_uri',
    ] as const) {
      assert.match(String(metadata[endpoint]), /^https:\/\//, endpoint)
    }
    assert.include(metadata.code_challenge_methods_supported, 'S256')
    assert.include(metadata.id_token_signing_alg_values_supported, 'RS256')
    assert.includeMembers(metadata.acr_values_supported ?? [], ['mfa-nextauth'])
  })

  test('publishes an RS256 signing key in the JWKS', async ({ assert }) => {
    const metadata = await fetchJson<ServerMetadata>(discoveryUrl)
    const jwks = await fetchJson<{ keys: JWK[] }>(metadata.jwks_uri!)

    const signingKeys = jwks.keys.filter(
      (key) => key.kty === 'RSA' && key.alg === 'RS256' && key.use === 'sig'
    )
    assert.isAbove(signingKeys.length, 0)
  })

  test('redirects the authorization URL to the CAS login page', async ({ assert }) => {
    const { url } = await startLogin({ ...config, acrValues: 'mfa-nextauth' })
    const response = await fetch(url, { redirect: 'follow' })
    const landing = new URL(response.url)

    assert.equal(response.status, 200)
    assert.equal(landing.origin, new URL(issuer).origin)
    assert.equal(landing.pathname, '/login')
    assert.isTrue(landing.searchParams.has('service'))
  })

  test('rejects a bogus authorization code with a typed error', async ({ assert }) => {
    const { url, cookies } = await startLogin(config)
    const driver = callbackDriver(
      config,
      { code: 'bogus-code', state: url.searchParams.get('state')! },
      cookies
    )

    const error = await catchError(driver.accessToken())
    assert.instanceOf(error, UlbOidcError)
    assert.equal(error.errorDescription, 'INVALID_TICKET')
  })

  test('rejects a bogus access token on userinfo with a typed error', async ({ assert }) => {
    const driver = new UlbOidcDriver(createContext('/'), config)
    const error = await catchError(driver.userFromToken('bogus-access-token'))
    assert.instanceOf(error, UlbOidcError)
    assert.equal(error.status, 401)
    assert.isNotEmpty(error.error)
  })

  test('rejects a bogus refresh token with a typed error', async ({ assert }) => {
    const driver = new UlbOidcDriver(createContext('/'), config)
    const error = await catchError(driver.refreshAccessToken('bogus-refresh-token'))
    assert.instanceOf(error, UlbOidcError)
    assert.equal(error.error, 'invalid_grant')
  })
})
