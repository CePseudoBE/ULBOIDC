import { Exception } from '@adonisjs/core/exceptions';
/**
 * Error raised by the ULB OIDC driver. `error` and `errorDescription` carry the
 * OAuth error returned by the server, or a local code such as `discovery_failed`,
 * `acr_mismatch` or an openid-client validation code (`OAUTH_JWT_CLAIM_COMPARISON_FAILED`…).
 */
export declare class UlbOidcError extends Exception {
    error: string;
    errorDescription?: string | undefined;
    static code: string;
    constructor(error: string, errorDescription?: string | undefined, options?: {
        status?: number;
        cause?: unknown;
    });
}
export declare function withUlbOidcErrors<T>(promise: Promise<T>): Promise<T>;
