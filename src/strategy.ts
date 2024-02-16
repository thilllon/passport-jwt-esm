import { Algorithm, Jwt, VerifyOptions, verify } from 'jsonwebtoken';
import { Strategy as PassportStrategy } from 'passport-strategy';
import { JwtFromRequestFunction } from './extractor';

/**
 * Interface for providing the secret or key for verification.
 */
interface SecretOrKeyProvider<T = any> {
  /**
   * Callback for secret or key provider.
   *
   * @param request - The request object from your framework (e.g., Express.Request)
   * @param rawJwtToken - The raw JWT token string
   * @param done - A function with the signature function(err, secret)
   */
  (request: T, rawJwtToken: any, done: (err: any, secretOrKey?: string | Buffer) => void): void;
}

interface BaseStrategyOptions {
  /**
   * Function that accepts a request as the only parameter and returns either the JWT as a string or null.
   * REQUIRED.
   */
  jwtFromRequest: JwtFromRequestFunction;
  /**
   * If defined, the issuer will be verified against this value.
   */
  issuer?: string | string[] | undefined;
  /**
   * If defined, the audience will be verified against this value.
   */
  audience?: string | string[] | undefined;
  /**
   * List of strings with the names of allowed algorithms (e.g., ["HS256", "HS384"]).
   */
  algorithms?: Algorithm[] | undefined;
  /**
   * If true, do not validate the expiration of the token.
   */
  ignoreExpiration?: boolean | undefined;

  /**
   * @deprecated
   * for backwards compatibility, still allowing you to pass
   * audience / issuer / algorithms / ignoreExpiration
   * on the options.
   */
  jsonWebTokenOptions?: VerifyOptions | undefined;
}
interface WithSecretOrKeyProvider extends BaseStrategyOptions {
  secretOrKeyProvider: SecretOrKeyProvider;
}
interface WithSecretOrKey extends BaseStrategyOptions {
  secretOrKey: string | Buffer;
}
type StrategyOptionsWithSecret =
  | Omit<WithSecretOrKey, 'secretOrKeyProvider'>
  | Omit<WithSecretOrKeyProvider, 'secretOrKey'>;
type StrategyOptionsWithRequest = StrategyOptionsWithSecret & {
  /**
   * If true, the verify callback will be called with args (request, jwt_payload, done_callback).
   */
  passReqToCallback: true;
};
type StrategyOptionsWithoutRequest = StrategyOptionsWithSecret & {
  /**
   * If true, the verify callback will be called with args (request, jwt_payload, done_callback).
   */
  passReqToCallback?: false;
};

/**
 * Union type for all possible Strategy options.
 */
type StrategyOptions = StrategyOptionsWithRequest | StrategyOptionsWithoutRequest;

/**
 * Callback used to verify the JWT payload.
 */
type VerifyCallback = (payload: any, done: VerifiedCallback) => void;

/**
 * Callback used to verify the JWT payload with request.
 */
type VerifyCallbackWithRequest<T = any> = (req: T, payload: any, done: VerifiedCallback) => void;

/**
 * Callback for the verified result.
 */
interface VerifiedCallback {
  (error: any, user?: unknown | false, info?: any): void;
}

export class Strategy extends PassportStrategy {
  public name = 'jwt';

  private _secretOrKeyProvider: SecretOrKeyProvider;
  private _verify: VerifyCallback | VerifyCallbackWithRequest<any>;
  private _jwtFromRequest: JwtFromRequestFunction<any>;
  private _passReqToCallback: boolean;
  private _verifyOptions: VerifyOptions;

  // Constructor overloading signatures
  constructor(options: StrategyOptionsWithoutRequest, verify: VerifyCallback);
  constructor(options: StrategyOptionsWithRequest, verify: VerifyCallbackWithRequest);

  // Unified constructor implementation
  constructor(options: StrategyOptions, verify: VerifyCallback | VerifyCallbackWithRequest) {
    super();
    if ('secretOrKeyProvider' in options && 'secretOrKey' in options) {
      throw new TypeError('Cannot specify both a secretOrKeyProvider and a secretOrKey');
    }

    if ('secretOrKeyProvider' in options) {
      this._secretOrKeyProvider = options.secretOrKeyProvider;
    } else if ('secretOrKey' in options) {
      this._secretOrKeyProvider = function (request, rawJwtToken, done) {
        done(null, options.secretOrKey);
      };
    } else {
      throw new Error('Invalid options. Must provide a secret or key');
    }

    this._verify = verify;
    this._jwtFromRequest = options.jwtFromRequest;
    this._passReqToCallback = options.passReqToCallback ?? false;

    const jsonWebTokenOptions = options.jsonWebTokenOptions || {};
    //for backwards compatibility, still allowing you to pass
    //audience / issuer / algorithms / ignoreExpiration
    //on the options.
    this._verifyOptions = Object.assign({}, jsonWebTokenOptions, {
      audience: options.audience,
      issuer: options.issuer,
      algorithms: options.algorithms,
      ignoreExpiration: !!options.ignoreExpiration,
    });
  }

  /**
   * Allow for injection of JWT Verifier.
   *
   * This improves testability by allowing tests to cleanly isolate failures in the JWT Verification
   * process from failures in the passport related mechanics of authentication.
   *
   * Note that this should only be replaced in tests.
   */
  static JwtVerifier = verify;

  /**
   * Authenticate request based on JWT obtained from header or post body
   */
  override authenticate(request: Express.Request, options?: any): void {
    const token = this._jwtFromRequest(request);

    if (!token) {
      return this.fail('No auth token', 401);
    }

    this._secretOrKeyProvider(request, token, (secretOrKeyError, secretOrKey?: string | Buffer) => {
      if (secretOrKeyError) {
        this.fail(secretOrKeyError);
      } else if (!secretOrKey) {
        throw new Error('Invalid secret or key');
      } else {
        verify(token, secretOrKey, this._verifyOptions, (jwtError: any, payload: any) => {
          if (jwtError) {
            return this.fail(jwtError);
          } else if (typeof secretOrKey === 'string') {
            // Pass the parsed token to the user
            const verified = (err: any, user: any, info: any) => {
              if (err) {
                return this.error(err);
              } else if (!user) {
                return this.fail(info);
              } else {
                return this.success(user, info);
              }
            };

            try {
              if (this._passReqToCallback) {
                this._verify(request, payload, verified);
              } else {
                (this._verify as any)(payload, verified);
              }
            } catch (err: any) {
              this.error(err);
            }
          }
        });
      }
    });
  }
}
