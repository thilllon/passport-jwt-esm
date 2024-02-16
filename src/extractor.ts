import url from 'node:url';
import { parseAuthHeader } from './parse-auth-header';

/**
 * - type of request is frame agnostic, so it can be used in `any` framework.
 */

/**
 * express http converts all headers to lower case.
 */
const AUTH_HEADER = 'authorization';
const BEARER_AUTH_SCHEME = 'bearer';

/**
 * Function that returns either the JWT as a string or null.
 */
export interface JwtFromRequestFunction<T = any> {
  (request: T): string | null;
}

export const ExtractJwt = {
  /**
   * Creates an extractor function to retrieve a token from the request header.
   *
   * @param {string} headerName - The name of the header to extract the token from.
   * @returns {JwtFromRequestFunction} A function that takes a request object and returns the extracted token.
   */
  fromHeader: function (headerName: string): JwtFromRequestFunction {
    return function (request) {
      let token: string | null = null;
      const _token = request.headers[headerName];
      if (_token && typeof _token === 'string') {
        token = _token;
      }
      return token;
    };
  },
  /**
   * Creates an extractor function to retrieve a token from a field in the request body.
   *
   * @param {string} fieldName - The name of the field to extract the token from.
   * @returns {JwtFromRequestFunction} A function that takes a request object and returns the extracted token.
   */
  fromBodyField: function (fieldName: string): JwtFromRequestFunction {
    return function (request) {
      let token: string | null = null;
      if (
        request.body &&
        Object.prototype.hasOwnProperty.call(request.body, fieldName)
      ) {
        token = request.body[fieldName];
      }
      return token;
    };
  },
  /**
   * Creates an extractor function to retrieve a token from a query parameter in the URL.
   *
   * @param {string} paramName - The name of the query parameter to extract the token from.
   * @returns {JwtFromRequestFunction} A function that takes a request object and returns the extracted token.
   */
  fromUrlQueryParameter: function (paramName: string): JwtFromRequestFunction {
    return function (request) {
      let token: string | null = null;
      const paredUrl = url.parse(request.url, true);
      if (
        paredUrl.query &&
        Object.prototype.hasOwnProperty.call(paredUrl.query, paramName)
      ) {
        token = paredUrl.query[paramName] as string;
      }
      return token;
    };
  },
  /**
   * Creates an extractor function to retrieve a token from the authorization header with a specific scheme.
   *
   * @param {string} authScheme - The authorization scheme (e.g., 'Bearer').
   * @returns {JwtFromRequestFunction} A function that takes a request object and returns the extracted token.
   */
  fromAuthHeaderWithScheme: function (
    authScheme: string,
  ): JwtFromRequestFunction {
    const authSchemeLowercase = authScheme.toLowerCase();
    return function (request) {
      let token: string | null = null;
      if (request.headers[AUTH_HEADER]) {
        const authParams = parseAuthHeader(request.headers[AUTH_HEADER]);
        if (
          authParams &&
          authSchemeLowercase === authParams.scheme.toLowerCase()
        ) {
          token = authParams.value;
        }
      }
      return token;
    };
  },
  /**
   * Creates an extractor function to retrieve a token from the authorization header as a Bearer token.
   *
   * @returns {JwtFromRequestFunction} A function that takes a request object and returns the extracted token.
   */
  fromAuthHeaderAsBearerToken: function (): JwtFromRequestFunction {
    return ExtractJwt.fromAuthHeaderWithScheme(BEARER_AUTH_SCHEME);
  },
  /**
   * Creates an extractor function that combines multiple extractor functions.
   *
   * @param {JwtFromRequestFunction[]} extractors - An array of extractor functions.
   * @returns {JwtFromRequestFunction} A function that takes a request object and returns the extracted token.
   */
  fromExtractors: function <T>(
    extractors: JwtFromRequestFunction<T>[],
  ): JwtFromRequestFunction<T> {
    return function (request: T) {
      let token: string | null = null;
      let index = 0;
      while (!token && index < extractors.length) {
        token = extractors[index](request);
        index++;
      }
      return token;
    };
  },
};
