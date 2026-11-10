import { Oauth2Driver } from '@adonisjs/ally';
import type { AllyUserContract, LiteralStringUnion, RedirectRequestContract } from '@adonisjs/ally/types';
import type { HttpContext } from '@adonisjs/core/http';
import * as client from 'openid-client';
export declare const DEFAULT_ISSUER = "https://auth.ulb.be/oidc";
export type UlbOidcScopes = 'openid' | 'profile' | 'email' | 'eduperson';
export type UlbOidcConfig = {
    clientId: string;
    clientSecret: string;
    callbackUrl: string;
    /** Defaults to https://auth.ulb.be/oidc */
    issuer?: string;
    /** Defaults to openid profile email eduperson */
    scopes?: LiteralStringUnion<UlbOidcScopes>[];
    /** Sent as `acr_values` and enforced on the ID token `acr` claim, e.g. 'mfa-nextauth' */
    acrValues?: string;
};
export type UlbOidcToken = {
    token: string;
    type: string;
    refreshToken?: string;
    expiresIn?: number;
    expiresAt?: Date;
    idToken?: string;
};
export type UlbOidcUserInfo = client.UserInfoResponse & {
    eduPersonAffiliation?: string | string[];
};
export type UlbOidcUser = AllyUserContract<UlbOidcToken> & {
    original: UlbOidcUserInfo;
};
export type UlbOidcLogoutOptions = {
    idTokenHint?: string;
    postLogoutRedirectUri?: string;
};
export declare class UlbOidcDriver extends Oauth2Driver<UlbOidcToken, UlbOidcScopes> {
    #private;
    config: UlbOidcConfig;
    protected authorizeUrl: string;
    protected accessTokenUrl: string;
    protected codeParamName: string;
    protected errorParamName: string;
    protected stateParamName: string;
    protected scopeParamName: string;
    protected scopesSeparator: string;
    protected stateCookieName: string;
    protected codeVerifierCookieName: string;
    protected nonceCookieName: string;
    protected nonceCookieValue?: string;
    constructor(ctx: HttpContext, config: UlbOidcConfig);
    protected loadState(): void;
    protected configureRedirectRequest(request: RedirectRequestContract<UlbOidcScopes>): void;
    protected configuration(): Promise<client.Configuration>;
    redirectUrl(callback?: (request: RedirectRequestContract<UlbOidcScopes>) => void): Promise<string>;
    accessDenied(): boolean;
    accessToken(): Promise<UlbOidcToken>;
    user(): Promise<UlbOidcUser>;
    userFromToken(token: string): Promise<AllyUserContract<{
        token: string;
        type: 'bearer';
    }>>;
    refreshAccessToken(refreshToken: string): Promise<UlbOidcToken>;
    logoutUrl(options?: UlbOidcLogoutOptions): Promise<string>;
    protected exchangeCode(): Promise<{
        token: UlbOidcToken;
        subject: string;
    }>;
    protected assertAcr(acr: string | undefined): void;
    protected callbackUrlWithQuery(): import("node:url").URL;
    protected fetchUserInfo(accessToken: string, expectedSubject: string | typeof client.skipSubjectCheck): Promise<UlbOidcUserInfo>;
}
export declare function ulbOidcService(config: UlbOidcConfig): (ctx: HttpContext) => UlbOidcDriver;
