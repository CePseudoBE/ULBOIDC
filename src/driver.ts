import { Oauth2Driver } from '@adonisjs/ally'
import type { HttpContext } from '@adonisjs/core/http'
import qs from 'qs'
import type {
  AllyDriverContract,
  AllyUserContract,
  ApiRequestContract,
  RedirectRequestContract,
} from '@adonisjs/ally/types'

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

  protected loadState() {
    super.loadState()
    console.log('Loaded state from cookie:', this.stateCookieValue)
  }

  protected configureRedirectRequest(request: RedirectRequestContract<UlbOidcScopes>) {
    request.param('response_type', 'code')
  }

  accessDenied() {
    return this.ctx.request.input('error') === 'access_denied'
  }

  async accessToken(): Promise<UlbOidcAccessToken> {
    const code = this.ctx.request.input('code')

    const body = qs.stringify({
      grant_type: 'authorization_code',
      code,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      redirect_uri: this.config.callbackUrl,
    })

    const response = await fetch(this.accessTokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    })

    const tokenResponse = (await response.json()) as {
      access_token: string
      token_type: string
      refresh_token?: string
      expires_in?: number
      id_token?: string
      scope?: string
    }

    if (!tokenResponse.access_token) {
      throw new Error('Aucun token reçu')
    }

    return {
      token: tokenResponse.access_token,
      type: 'bearer',
    }
  }

  async user(
    callback?: (request: ApiRequestContract) => void
  ): Promise<AllyUserContract<UlbOidcAccessToken>> {
    const accessToken = await this.accessToken()

    const request = this.httpClient(this.config.userInfoUrl || this.userInfoUrl)

    request.header('Authorization', `Bearer ${accessToken.token}`)
    request.header('Accept', 'application/json')

    if (typeof callback === 'function') {
      callback(request)
    }

    try {
      const response = await request.get()
      const userInfo = await response.body
      console.log('[OIDC] ➤ Status HTTP:', response.status)

      if ('text' in response) {
        const raw = await response.text()
        console.log('[OIDC] ➤ Contenu brut:', raw)
      } else {
        console.log('[OIDC] ➤ Pas de méthode .text() sur la réponse')
      }

      if (!userInfo || !userInfo.email) {
        console.warn('[OIDC] ⚠️ Réponse inattendue: userInfo ne contient pas "email"')
      }

      return {
        id: userInfo.sub || userInfo.id || 'unknown',
        nickName: userInfo.preferred_username || userInfo.cn || 'unknown',
        name: userInfo.name || `${userInfo.given_name ?? ''} ${userInfo.family_name ?? ''}`.trim(),
        email: userInfo.email || userInfo.mail || 'unknown',
        emailVerificationState: 'unsupported',
        avatarUrl: null,
        original: userInfo,
        token: accessToken,
      }
    } catch (error) {
      console.error('[OIDC] ❌ Erreur lors de la récupération du profil utilisateur')
      console.error('[OIDC] ➤ Message:', error.message)
      console.error('[OIDC] ➤ Stack:', error.stack)
      throw error
    }
  }

  /**
   * Récupère les informations de l'utilisateur à partir d'un token d'accès.
   */
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

/**
 * Fonction de service pour initialiser le pilote UlbOidcDriver.
 */
export function ulbOidcService(config: UlbOidcConfig): (ctx: HttpContext) => UlbOidcDriver {
  return (ctx) => new UlbOidcDriver(ctx, config)
}
