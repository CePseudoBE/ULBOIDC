import { Oauth2Driver, errors } from '@adonisjs/ally';
import * as client from 'openid-client';
import { UlbOidcError, withUlbOidcErrors } from './errors.js';
export const DEFAULT_ISSUER = 'https://auth.ulb.be/oidc';
const DEFAULT_SCOPES = ['openid', 'profile', 'email', 'eduperson'];
const DISCOVERY_TIMEOUT_SECONDS = 10;
const configurations = new Map();
function getConfiguration(config) {
    const issuer = config.issuer ?? DEFAULT_ISSUER;
    const key = `${issuer} ${config.clientId}`;
    let configuration = configurations.get(key);
    if (!configuration) {
        configuration = discover(issuer, config);
        configurations.set(key, configuration);
        configuration.catch(() => configurations.delete(key));
    }
    return configuration;
}
async function discover(issuer, config) {
    try {
        return await client.discovery(new URL(issuer), config.clientId, { client_secret: config.clientSecret, id_token_signed_response_alg: 'RS256' }, undefined, {
            timeout: DISCOVERY_TIMEOUT_SECONDS,
            // Without it openid-client trusts TLS and skips the ID token signature check against the JWKS.
            execute: [client.enableNonRepudiationChecks],
        });
    }
    catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        throw new UlbOidcError('discovery_failed', `Unable to load the OpenID configuration of ${issuer}: ${reason}`, { status: 503, cause: error });
    }
}
function toToken(tokens) {
    return {
        token: tokens.access_token,
        type: tokens.token_type,
        refreshToken: tokens.refresh_token,
        expiresIn: tokens.expires_in,
        expiresAt: tokens.expires_in === undefined ? undefined : new Date(Date.now() + tokens.expires_in * 1000),
        idToken: tokens.id_token,
    };
}
function toUser(info) {
    return {
        id: info.sub,
        nickName: info.preferred_username ?? info.sub,
        name: info.name ?? [info.given_name, info.family_name].filter(Boolean).join(' '),
        email: info.email ?? null,
        emailVerificationState: 'unsupported',
        avatarUrl: null,
        original: info,
    };
}
export class UlbOidcDriver extends Oauth2Driver {
    config;
    authorizeUrl = '';
    // The code exchange goes through openid-client, not Ally's HTTP client.
    accessTokenUrl = '';
    codeParamName = 'code';
    errorParamName = 'error';
    stateParamName = 'state';
    scopeParamName = 'scope';
    scopesSeparator = ' ';
    stateCookieName = 'ulb_oidc_oauth_state';
    codeVerifierCookieName = 'ulb_oidc_oauth_code_verifier';
    nonceCookieName = 'ulb_oidc_oauth_nonce';
    nonceCookieValue;
    #codeExchange;
    constructor(ctx, config) {
        super(ctx, config);
        this.config = config;
        this.loadState();
    }
    loadState() {
        super.loadState();
        this.nonceCookieValue = this.ctx.request.encryptedCookie(this.nonceCookieName);
        this.ctx.response.clearCookie(this.nonceCookieName);
    }
    configureRedirectRequest(request) {
        const nonce = client.randomNonce();
        this.ctx.response.encryptedCookie(this.nonceCookieName, nonce, {
            sameSite: false,
            httpOnly: true,
        });
        request.scopes(this.config.scopes ?? DEFAULT_SCOPES);
        request.param('response_type', 'code');
        request.param('nonce', nonce);
        if (this.config.acrValues)
            request.param('acr_values', this.config.acrValues);
    }
    configuration() {
        return getConfiguration(this.config);
    }
    async redirectUrl(callback) {
        const configuration = await this.configuration();
        this.authorizeUrl = configuration.serverMetadata().authorization_endpoint ?? '';
        return super.redirectUrl(callback);
    }
    accessDenied() {
        return this.getError() === 'access_denied';
    }
    async accessToken() {
        const { token } = await this.exchangeCode();
        return token;
    }
    async user() {
        const { token, subject } = await this.exchangeCode();
        const info = await this.fetchUserInfo(token.token, subject);
        return { ...toUser(info), token };
    }
    async userFromToken(token) {
        // No ID token here to compare `sub` against; openid-client marks the flag deprecated only as a warning.
        const info = await this.fetchUserInfo(token, client.skipSubjectCheck);
        return { ...toUser(info), token: { token, type: 'bearer' } };
    }
    async refreshAccessToken(refreshToken) {
        const configuration = await this.configuration();
        return toToken(await withUlbOidcErrors(client.refreshTokenGrant(configuration, refreshToken)));
    }
    async logoutUrl(options = {}) {
        const configuration = await this.configuration();
        const parameters = {};
        if (options.idTokenHint)
            parameters.id_token_hint = options.idTokenHint;
        if (options.postLogoutRedirectUri) {
            parameters.post_logout_redirect_uri = options.postLogoutRedirectUri;
        }
        return client.buildEndSessionUrl(configuration, parameters).href;
    }
    async exchangeCode() {
        if (this.#codeExchange)
            return this.#codeExchange;
        if (this.hasError())
            throw new errors.E_OAUTH_MISSING_CODE([this.codeParamName]);
        if (this.stateMisMatch())
            throw new errors.E_OAUTH_STATE_MISMATCH();
        const configuration = await this.configuration();
        const tokens = await withUlbOidcErrors(client.authorizationCodeGrant(configuration, this.callbackUrlWithQuery(), {
            pkceCodeVerifier: this.getPkceCodeVerifierForAccessToken() ?? undefined,
            expectedState: this.stateCookieValue,
            expectedNonce: this.nonceCookieValue,
            idTokenExpected: true,
        }));
        const claims = tokens.claims();
        if (!claims)
            throw new UlbOidcError('invalid_response', 'The token response has no ID token');
        this.assertAcr(typeof claims.acr === 'string' ? claims.acr : undefined);
        this.#codeExchange = { token: toToken(tokens), subject: claims.sub };
        return this.#codeExchange;
    }
    assertAcr(acr) {
        if (!this.config.acrValues)
            return;
        if (acr && this.config.acrValues.split(' ').includes(acr))
            return;
        throw new UlbOidcError('acr_mismatch', `Expected acr "${this.config.acrValues}", received "${acr ?? ''}"`, { status: 401 });
    }
    // openid-client derives redirect_uri from this URL, so it must be the configured callback, not the proxied request URL.
    callbackUrlWithQuery() {
        const url = new URL(this.config.callbackUrl);
        url.search = new URL(this.ctx.request.url(true), url).search;
        return url;
    }
    async fetchUserInfo(accessToken, expectedSubject) {
        const configuration = await this.configuration();
        return withUlbOidcErrors(client.fetchUserInfo(configuration, accessToken, expectedSubject));
    }
}
export function ulbOidcService(config) {
    return (ctx) => new UlbOidcDriver(ctx, config);
}
