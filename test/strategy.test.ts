import { Strategy } from '../src/strategy';
describe('Strategy', () => {
  describe('instantiation', function () {
    it('should be named jwt', () => {
      expect(
        new Strategy(
          {
            secretOrKey: 'secret',
            jwtFromRequest: () => 'some-valid-jwt',
          },
          () => {},
        ).name,
      ).toBe('jwt');
    });

    it('should throw if constructed with both a secretOrKey and a secretOrKeyProvider', () => {
      expect(() => {
        new Strategy(
          {
            secretOrKey: 'secret',
            secretOrKeyProvider: (request: Request, token: string, done: any) => {},
            jwtFromRequest: () => 'some-valid-jwt',
          },
          () => {},
        );
      }).toThrow(new TypeError('Cannot specify both a secretOrKeyProvider and a secretOrKey'));
    });
  });
});
