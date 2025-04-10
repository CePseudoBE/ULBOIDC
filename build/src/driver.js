import { Oauth2Driver } from '@adonisjs/ally';
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
    /**
     * Configure les paramètres supplémentaires pour la requête de redirection.
     * Ici, on s'assure que le paramètre 'response_type' est défini sur 'code'.
     */
    configureRedirectRequest(request) {
        request.param('response_type', 'code');
        // Ajoute d'autres paramètres si nécessaire
    }
    /**
     * Vérifie si l'accès a été refusé par l'utilisateur.
     */
    accessDenied() {
        return this.ctx.request.input('error') === 'access_denied';
    }
    /**
     * Récupère les informations de l'utilisateur à partir du fournisseur OIDC.
     */
    async user(callback) {
        console.log('ca passe ici');
        const accessToken = await this.accessToken();
        console.log(accessToken);
        const request = this.httpClient(this.config.userInfoUrl || this.userInfoUrl);
        request.header('Authorization', `Bearer ${accessToken.token}`);
        if (typeof callback === 'function') {
            callback(request);
        }
        console.log('ça passe');
        const userInfo = await request.get().then((res) => res.body());
        console.log(userInfo);
        return {
            id: userInfo,
            nickName: userInfo,
            name: userInfo,
            email: userInfo.email,
            emailVerificationState: 'unsupported',
            avatarUrl: null,
            original: userInfo,
            token: accessToken,
        };
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
