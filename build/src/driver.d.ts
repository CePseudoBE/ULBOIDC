import { Oauth2Driver } from '@adonisjs/ally';
import type { HttpContext } from '@adonisjs/core/http';
import type { AllyDriverContract, AllyUserContract, ApiRequestContract } from '@adonisjs/ally/types';
export type UlbOidcAccessToken = {
    token: string;
    type: 'bearer';
};
export type UlbOidcScopes = 'openid' | 'profile' | 'email' | 'eduperson';
export type UlbOidcConfig = {
    clientId: string;
    clientSecret: string;
    callbackUrl: string;
    authorizeUrl?: string;
    accessTokenUrl?: string;
    userInfoUrl?: string;
};
export declare class UlbOidcDriver extends Oauth2Driver<UlbOidcAccessToken, UlbOidcScopes> implements AllyDriverContract<UlbOidcAccessToken, UlbOidcScopes> {
    config: UlbOidcConfig;
    protected authorizeUrl: string;
    protected accessTokenUrl: string;
    protected userInfoUrl: string;
    protected codeParamName: string;
    protected errorParamName: string;
    protected stateCookieName: string;
    protected stateParamName: string;
    protected scopeParamName: string;
    protected scopesSeparator: string;
    protected scopes: UlbOidcScopes[];
    constructor(ctx: HttpContext, config: UlbOidcConfig);
    accessDenied(): boolean;
    user(callback?: (request: ApiRequestContract) => void): Promise<AllyUserContract<UlbOidcAccessToken>>;
    userFromToken(token: string, callback?: (request: ApiRequestContract) => void): Promise<AllyUserContract<{
        token: string;
        type: 'bearer';
    }>>;
}
export declare function ulbOidcService(config: UlbOidcConfig): (ctx: HttpContext) => UlbOidcDriver;
