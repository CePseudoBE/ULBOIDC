import { Oauth2Driver } from '@adonisjs/ally';
import type { HttpContext } from '@adonisjs/core/http';
import type { AllyDriverContract, AllyUserContract, ApiRequestContract, RedirectRequestContract } from '@adonisjs/ally/types';
export type UlbOidcAccessToken = {
    token: string;
    type: 'bearer';
};
export type UlbOidcScopes = 'openid' | 'profile' | 'email' | 'eduperson';
export type UlbOidcConfig = {
    clientId: string;
    clientSecret: string;
    callbackUrl: string;
    serverUrl: string;
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
    constructor(ctx: HttpContext, config: UlbOidcConfig);
    protected loadState(): void;
    /**
     * Configure les paramètres supplémentaires pour la requête de redirection.
     * Ici, on s'assure que le paramètre 'response_type' est défini sur 'code'.
     */
    protected configureRedirectRequest(request: RedirectRequestContract<UlbOidcScopes>): void;
    /**
     * Vérifie si l'accès a été refusé par l'utilisateur.
     */
    accessDenied(): boolean;
    accessToken(): Promise<UlbOidcAccessToken>;
    /**
     * Récupère les informations de l'utilisateur à partir du fournisseur OIDC.
     */
    user(callback?: (request: ApiRequestContract) => void): Promise<AllyUserContract<UlbOidcAccessToken>>;
    /**
     * Récupère les informations de l'utilisateur à partir d'un token d'accès.
     */
    userFromToken(token: string, callback?: (request: ApiRequestContract) => void): Promise<AllyUserContract<{
        token: string;
        type: 'bearer';
    }>>;
}
/**
 * Fonction de service pour initialiser le pilote UlbOidcDriver.
 */
export declare function ulbOidcService(config: UlbOidcConfig): (ctx: HttpContext) => UlbOidcDriver;
