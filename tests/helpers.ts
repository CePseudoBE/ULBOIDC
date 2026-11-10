import { IncomingMessage } from 'node:http'
import { Socket } from 'node:net'
import { EncryptionFactory } from '@adonisjs/core/factories/encryption'
import { RequestFactory } from '@adonisjs/core/factories/http'
import type { HttpContext } from '@adonisjs/core/http'
import { UlbOidcDriver, type UlbOidcConfig } from '../index.js'

const encryption = new EncryptionFactory().create()

export function createContext(url: string, cookies: Record<string, string> = {}): HttpContext {
  const req = new IncomingMessage(new Socket())
  req.method = 'GET'
  req.url = url
  req.headers.cookie = Object.entries(cookies)
    .map(([name, value]) => `${name}=${value}`)
    .join('; ')
  return new RequestFactory().merge({ req, encryption }).create().ctx!
}

function responseCookies(ctx: HttpContext): Record<string, string> {
  const header = ctx.response.getHeader('set-cookie') ?? []
  const cookies: Record<string, string> = {}
  for (const cookie of [header].flat()) {
    const [name, value] = String(cookie).split(';')[0].split('=')
    if (value) cookies[name] = value
  }
  return cookies
}

/**
 * Runs `redirect()` and returns the authorization URL plus the cookies a
 * browser would send back on the callback.
 */
export async function startLogin(config: UlbOidcConfig) {
  const ctx = createContext('/login')
  await new UlbOidcDriver(ctx, config).redirect()
  return {
    url: new URL(String(ctx.response.getHeader('location'))),
    cookies: responseCookies(ctx),
  }
}

export function callbackDriver(
  config: UlbOidcConfig,
  query: Record<string, string>,
  cookies: Record<string, string> = {}
) {
  const ctx = createContext(`/auth/callback?${new URLSearchParams(query)}`, cookies)
  return new UlbOidcDriver(ctx, config)
}

export async function catchError(promise: Promise<unknown>): Promise<any> {
  try {
    await promise
  } catch (error) {
    return error
  }
  throw new Error('Expected the promise to reject')
}
