import { Request } from 'express';
import { ExtractJwt } from '../src';

class RequestMock {
  method = 'GET';
  url = '/';
  headers = {};
}

describe('Token extractor', () => {
  describe('fromHeader', () => {
    const extractor = ExtractJwt.fromHeader('test_header');

    it('should return null no when token is present', () => {
      const req = new RequestMock() as Request;
      expect(extractor(req)).toBeNull();
    });

    it('should return the value from the specified header', () => {
      const req = new RequestMock() as Request;
      req.headers['test_header'] = 'abcd123';
      expect(extractor(req)).toBe('abcd123');
    });
  });

  describe('fromBodyField', () => {
    const extractor = ExtractJwt.fromBodyField('test_field');

    it('should return null when no body is present', () => {
      const req = new RequestMock() as Request;
      expect(extractor(req)).toBeNull();
    });

    it('should return null when the specified body field is not present', () => {
      const req = new RequestMock() as Request;
      req.body = {};
      expect(extractor(req)).toBeNull();
    });

    it('should return the value from the specified body field', () => {
      const req = new RequestMock() as Request;
      req.body = {};
      req.body.test_field = 'abcd123';
      expect(extractor(req)).toBe('abcd123');
    });

    it('should work properly with querystring', () => {
      const req = new RequestMock() as Request;
      const querystring = require('querystring');
      req.body = querystring.parse('test_field=abcd123');

      expect(extractor(req)).toBe('abcd123');
    });
  });

  describe('fromUrlQueryParameter', () => {
    const extractor = ExtractJwt.fromUrlQueryParameter('test_param');
    it('should return null when the specified paramter is not present', () => {
      const req = new RequestMock() as Request;

      expect(extractor(req)).toBeNull();
    });

    it('should return the value from the specified parameter', () => {
      const req = new RequestMock() as Request;
      req.url += '?test_param=abcd123';

      expect(extractor(req)).toBe('abcd123');
    });
  });

  describe('fromAuthHeaderWithScheme', () => {
    const extractor = ExtractJwt.fromAuthHeaderWithScheme('TEST_SCHEME');
    it('should return null when no auth header is present', () => {
      const req = new RequestMock() as Request;
      expect(extractor(req)).toBeNull();
    });

    it('should return null when the auth header is present but the auth scheme doesnt match', () => {
      const req = new RequestMock() as Request;
      req.headers['authorization'] = 'NOT_TEST_SCHEME abcd123';
      expect(extractor(req)).toBeNull();
    });

    it('should return the value from the authorization header with specified auth scheme', () => {
      const req = new RequestMock() as Request;
      req.headers['authorization'] = 'TEST_SCHEME abcd123';

      expect(extractor(req)).toBe('abcd123');
    });

    it('should perform a case-insensivite string comparison', () => {
      const req = new RequestMock() as Request;
      req.headers['authorization'] = 'test_scheme abcd123';
      expect(extractor(req)).toBe('abcd123');
    });
  });
  describe('fromAuthHeader', () => {
    const extractor = ExtractJwt.fromAuthHeaderAsBearerToken();
    it('should return the value from the authorization header with default JWT auth scheme', () => {
      const req = new RequestMock() as Request;
      req.headers['authorization'] = 'bearer abcd123';
      expect(extractor(req)).toBe('abcd123');
    });
  });

  describe('fromExtractors', () => {
    const extractor = ExtractJwt.fromExtractors([
      ExtractJwt.fromAuthHeaderAsBearerToken(),
      ExtractJwt.fromHeader('authorization'),
    ]);

    it('should return null when no extractor extracts token', () => {
      const req = new RequestMock() as Request;
      expect(extractor(req)).toBeNull();
    });

    it('should return token found by least extractor', () => {
      const req = new RequestMock() as Request;
      req.headers['authorization'] = 'abcd123';
      expect(extractor(req)).toBe('abcd123');
    });

    it('should return token found by first extractor', () => {
      const req = new RequestMock() as Request;
      req.headers['authorization'] = 'bearer abcd123';
      expect(extractor(req)).toBe('abcd123');
    });
  });
});
