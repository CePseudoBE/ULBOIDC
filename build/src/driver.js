import { Oauth2Driver } from '@adonisjs/ally';
import qs from 'qs';
export class UlbOidcDriver extends Oauth2Driver {
    config;
    authorizeUrl;
    accessTokenUrl;
    userInfoUrl;
    codeParamName = 'code';
    errorParamName = 'error';
    stateCookieName = 'ulb_oidc_oauth_state';
    stateParamName = 'state';
    scopeParamName = 'scope';
    scopesSeparator = ' ';
    constructor(ctx, config) {
        super(ctx, config);
        this.config = config;
        this.authorizeUrl = config.authorizeUrl || `https://${config.serverUrl}/oidc/oidcAuthorize`;
        this.accessTokenUrl =
            config.accessTokenUrl || `https://${config.serverUrl}/oidc/oidcAccessToken`;
        this.userInfoUrl = config.userInfoUrl || `https://${config.serverUrl}/oidc/oidcProfile`;
        this.loadState();
    }
    loadState() {
        super.loadState();
    }
    configureRedirectRequest(request) {
        request.param('response_type', 'code');
        request.scopes(['openid', 'profile', 'email', 'eduperson']);
    }
    accessDenied() {
        return this.ctx.request.input('error') === 'access_denied';
    }
    async accessToken() {
        const code = this.ctx.request.input('code');
        const body = qs.stringify({
            grant_type: 'authorization_code',
            code,
            client_id: this.config.clientId,
            client_secret: this.config.clientSecret,
            redirect_uri: this.config.callbackUrl,
        });
        const response = await fetch(this.accessTokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body,
        });
        const tokenResponse = (await response.json());
        if (!tokenResponse.access_token) {
            throw new Error('Aucun token reçu');
        }
        return {
            token: tokenResponse.access_token,
            type: 'bearer',
        };
    }
    async user(callback) {
        const accessToken = await this.accessToken();
        const request = this.httpClient(this.config.userInfoUrl || this.userInfoUrl);
        request.header('Authorization', `Bearer ${accessToken.token}`);
        request.header('Accept', 'application/json');
        if (typeof callback === 'function') {
            callback(request);
        }
        try {
            const userInfo = await request.get(); // pas .body(), pas .json()
            console.log('[OIDC] ✅ userInfo brut reçu:', userInfo);
            return {
                id: userInfo.sub || userInfo.id || 'unknown',
                nickName: userInfo.preferred_username || userInfo.cn || 'unknown',
                name: userInfo.name || `${userInfo.given_name ?? ''} ${userInfo.family_name ?? ''}`.trim(),
                email: userInfo.email || userInfo.mail || 'unknown',
                emailVerificationState: 'unsupported',
                avatarUrl: null,
                original: userInfo,
                token: accessToken,
            };
        }
        catch (error) {
            console.error('[OIDC] ❌ Erreur lors de la récupération du profil utilisateur');
            console.error('[OIDC] ➤ Message:', error.message);
            console.error('[OIDC] ➤ Stack:', error.stack);
            throw error;
        }
    }
    /**
     * Récupère les informations de l'utilisateur à partir d'un token d'accès.
     */
    async userFromToken(token, callback) {
        const request = this.httpClient(this.config.userInfoUrl || this.userInfoUrl);
        request.header('Authorization', `Bearer ${token}`);
        if (typeof callback === 'function') {
            callback(request);
        }
        const userInfo = await request.get().then((res) => res.body());
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
        };
    }
}
/**
 * Fonction de service pour initialiser le pilote UlbOidcDriver.
 */
export function ulbOidcService(config) {
    return (ctx) => new UlbOidcDriver(ctx, config);
}
