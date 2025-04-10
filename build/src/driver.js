import { Oauth2Driver } from '@adonisjs/ally';
export class UlbOidcDriver extends Oauth2Driver {
    config;
    authorizeUrl = 'https://auth.ulb.be/oidc/oidcAuthorize';
    accessTokenUrl = 'https://auth.ulb.be/oidc/oidcAccessToken';
    userInfoUrl = 'https://auth.ulb.be/oidc/oidcProfile';
    codeParamName = 'code';
    errorParamName = 'error';
    stateCookieName = 'ulb_oidc_oauth_state';
    stateParamName = 'state';
    scopeParamName = 'scope';
    scopesSeparator = ' ';
    scopes = ['openid', 'profile', 'email', 'eduperson'];
    constructor(ctx, config) {
        super(ctx, config);
        this.config = config;
        this.loadState();
    }
    accessDenied() {
        return this.ctx.request.input('error') === 'access_denied';
    }
    async user(callback) {
        const accessToken = await this.accessToken();
        const request = this.httpClient(this.config.userInfoUrl || this.userInfoUrl);
        request.header('Authorization', `Bearer ${accessToken.token}`);
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
            token: accessToken,
        };
    }
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
export function ulbOidcService(config) {
    return (ctx) => new UlbOidcDriver(ctx, config);
}
