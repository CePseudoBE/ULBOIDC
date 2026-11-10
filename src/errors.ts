import { Exception } from '@adonisjs/core/exceptions'
import {
  AuthorizationResponseError,
  ResponseBodyError,
  WWWAuthenticateChallengeError,
} from 'openid-client'

/**
 * Error raised by the ULB OIDC driver. `error` and `errorDescription` carry the
 * OAuth error returned by the server, or a local code such as `discovery_failed`,
 * `acr_mismatch` or an openid-client validation code (`OAUTH_JWT_CLAIM_COMPARISON_FAILED`…).
 */
export class UlbOidcError extends Exception {
  static code = 'E_ULB_OIDC'

  constructor(
    public error: string,
    public errorDescription?: string,
    options?: { status?: number; cause?: unknown }
  ) {
    super(errorDescription ? `${error}: ${errorDescription}` : error, {
      status: options?.status ?? 400,
      cause: options?.cause,
    })
  }
}

async function toUlbOidcError(error: unknown): Promise<unknown> {
  if (error instanceof UlbOidcError) return error
  if (error instanceof ResponseBodyError || error instanceof AuthorizationResponseError) {
    const status = error instanceof ResponseBodyError ? error.status : undefined
    return new UlbOidcError(error.error, error.error_description, { status, cause: error })
  }
  if (error instanceof WWWAuthenticateChallengeError) {
    const parameters = error.cause[0]?.parameters
    return new UlbOidcError(parameters?.error ?? 'invalid_token', parameters?.error_description, {
      status: error.status,
      cause: error,
    })
  }
  if (error instanceof Error && error.cause instanceof Response) {
    return fromNonConformResponse(error, error.cause)
  }
  if (error instanceof Error) {
    const code = 'code' in error && typeof error.code === 'string' ? error.code : 'invalid_response'
    return new UlbOidcError(code, error.message, { cause: error })
  }
  return error
}

export async function withUlbOidcErrors<T>(promise: Promise<T>): Promise<T> {
  try {
    return await promise
  } catch (error) {
    throw await toUlbOidcError(error)
  }
}

// CAS answers some failures outside the OAuth format (HTTP 500 Spring body, 401 without WWW-Authenticate): openid-client then keeps the raw response as cause.
async function fromNonConformResponse(error: Error, response: Response): Promise<UlbOidcError> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>
  const serverError = typeof body.error === 'string' ? body.error : 'invalid_response'
  const description = [body.error_description, body.message].find(
    (value): value is string => typeof value === 'string'
  )
  return new UlbOidcError(serverError, description ?? error.message, {
    status: response.status,
    cause: error,
  })
}
