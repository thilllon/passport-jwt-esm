import { parseAuthHeader } from '../src/parse-auth-header';

describe('Parsing Auth Header field-value', () => {
  it('Should handle single space separated values', () => {
    expect(parseAuthHeader('SCHEME VALUE')).toEqual({
      scheme: 'SCHEME',
      value: 'VALUE',
    });
  });

  it('Should handle CRLF separator', () => {
    expect(parseAuthHeader('SCHEME\nVALUE')).toEqual({
      scheme: 'SCHEME',
      value: 'VALUE',
    });
  });

  it('Should handle malformed authentication headers with no scheme', () => {
    expect(parseAuthHeader('malformed')).toBeNull();
  });

  it('Should return null when the auth header is not a string', () => {
    expect(parseAuthHeader(undefined as any)).toBeNull();
    expect(parseAuthHeader(1234 as any)).toBeNull();
    expect(parseAuthHeader(null as any)).toBeNull();
    expect(parseAuthHeader({} as any)).toBeNull();
  });
});
