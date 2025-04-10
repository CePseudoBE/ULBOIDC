import { Oauth2Driver } from '@adonisjs/ally'
import type { HttpContext } from '@adonisjs/core/http'
import type { AllyDriverContract, AllyUserContract, ApiRequestContract } from '@adonisjs/ally/types'

export type UlbOidcAccessToken = {
  token: string
  type: 'bearer'
}

export type UlbOidcScopes = 'openid' | 'profile' | 'email' | 'eduperson'

export type UlbOidcConfig = {
  clientId: string
  clientSecret: string
  callbackUrl: string
  serverUrl: string
  authorizeUrl?: string
  accessTokenUrl?: string
  userInfoUrl?: string
}

export class UlbOidcDriver
  extends Oauth2Driver<UlbOidcAccessToken, UlbOidcScopes>
  implements AllyDriverContract<UlbOidcAccessToken, UlbOidcScopes>
{
  protected authorizeUrl: string
  protected accessTokenUrl: string
  protected userInfoUrl: string

  protected codeParamName = 'code'
  protected errorParamName = 'error'
  protected stateCookieName = 'ulb_oidc_oauth_state'
  protected stateParamName = 'state'
  protected scopeParamName = 'scope'
  protected scopesSeparator = ' '

  constructor(
    ctx: HttpContext,
    public config: UlbOidcConfig
  ) {
    super(ctx, config)
    this.authorizeUrl = config.authorizeUrl || `https://${config.serverUrl}/oidc/oidcAuthorize`
    this.accessTokenUrl =
      config.accessTokenUrl || `https://${config.serverUrl}/oidc/oidcAccessToken`
    this.userInfoUrl = config.userInfoUrl || `https://${config.serverUrl}/oidc/oidcProfile`
    this.loadState()
  }

  accessDenied() {
    return this.ctx.request.input('error') === 'access_denied'
  }

  async user(
    callback?: (request: ApiRequestContract) => void
  ): Promise<AllyUserContract<UlbOidcAccessToken>> {
    const accessToken = await this.accessToken()
    const request = this.httpClient(this.config.userInfoUrl || this.userInfoUrl)

    request.header('Authorization', `Bearer ${accessToken.token}`)

    if (typeof callback === 'function') {
      callback(request)
    }

    const userInfo = await request.get().then((res) => res.body())

    return {
      id: userInfo.sub,
      nickName: userInfo.preferred_username,
      name: `${userInfo.given_name} ${userInfo.family_name}`,
      email: userInfo.email,
      emailVerificationState: 'unsupported',
      avatarUrl: null,
      original: userInfo,
      token: accessToken,
    }
  }

  async userFromToken(
    token: string,
    callback?: (request: ApiRequestContract) => void
  ): Promise<AllyUserContract<{ token: string; type: 'bearer' }>> {
    const request = this.httpClient(this.config.userInfoUrl || this.userInfoUrl)

    request.header('Authorization', `Bearer ${token}`)

    if (typeof callback === 'function') {
      callback(request)
    }

    const userInfo = await request.get().then((res) => res.body())

    return {
      id: userInfo.sub,
      nickName: userInfo.preferred_username,
      name: `${userInfo.given_name} ${userInfo.family_name}`,
      email: userInfo.email,
      emailVerificationState: 'unsupported',
      avatarUrl: null,
      original: userInfo,
      token: {
        token,
        type: 'bearer',
      },
    }
  }
}

export function ulbOidcService(config: UlbOidcConfig): (ctx: HttpContext) => UlbOidcDriver {
  return (ctx) => new UlbOidcDriver(ctx, config)
}
