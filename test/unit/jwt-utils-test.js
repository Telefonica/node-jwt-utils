'use strict';

var jwt = require('../../lib/jwt-utils');
var errors = require('../../lib/errors');
var fs = require('fs');

/*jshint -W098 */
describe('Jwt Utils Tests', function() {
  var jwtUtils;

  beforeEach(function() {
    jwtUtils = jwt();
  });

  it('should be error when header is null', function() {
    jwtUtils.buildJWT({'payload': 'payloadData'}, null, 'hashKey', function(err, token) {
      expect(err).to.be.apiError(errors.MISSING_REQUIRED_HEADER());
      expect(token).not.to.exist;
    });
  });

  it('should be error when header has an invalid algorithm', function() {
    jwtUtils.buildJWT({'payload': 'payloadData'}, {alg: 'HS4353'}, 'hashKey', function(err, token) {
      expect(err).to.be.apiError(errors.ALGORITHM_NOT_SUPPORTED());
      expect(token).not.to.exist;
    });
  });

  it('should be error when key is null', function() {
    jwtUtils.buildJWT({'payload': 'payloadData'}, {}, null, function(err, token) {
      expect(err).to.be.apiError(errors.MISSING_REQUIRED_KEY());
      expect(token).not.to.exist;
    });
  });

  it('should be error when kid is null', function() {
    jwtUtils.buildJWT({'payload': 'payloadData'}, {}, 'hashKey', function(err, token) {
      expect(err).to.be.apiError(errors.MISSING_REQUIRED_KID());
      expect(token).not.to.exist;
    });
  });

  it('should be generate a token with key, payload and kid', function() {
    var payload = {
      'request': {
        'continue': 'http://your-service.com/continue-handler',
        'foceLogin': true
      },
      'aud': ['tdaf-accounts'],
      'iss': 'something-to-help-trace',
      'jti': 'be4ea97e-bad8-45d6-a069-928b53441f4c',
      'iat': 1374078871
    };

    var hashKey = '796f75722d7365637265742d6b657923';
    var kid = 'your-client-id';

    jwtUtils.buildJWT(payload, {alg: 'HS256', kid: kid}, hashKey, function(err, token) {
      expect(err).not.to.exist;
      expect(token).to.exist;
      expect(token).to.equal('eyJhbGciOiJIUzI1NiIsImtp' +
          'ZCI6InlvdXItY2xpZW50LWlkIn0.eyJyZXF1ZXN0Ijp' +
          '7ImNvbnRpbnVlIjoiaHR0cDovL3lvdXItc2VydmljZS' +
          '5jb20vY29udGludWUtaGFuZGxlciIsImZvY2VMb2dpb' +
          'iI6dHJ1ZX0sImF1ZCI6WyJ0ZGFmLWFjY291bnRzIl0s' +
          'ImlzcyI6InNvbWV0aGluZy10by1oZWxwLXRyYWNlIiw' +
          'ianRpIjoiYmU0ZWE5N2UtYmFkOC00NWQ2LWEwNjktOT' +
          'I4YjUzNDQxZjRjIiwiaWF0IjoxMzc0MDc4ODcxLCJle' +
          'HAiOjEzNzQwNzk0NzF9.e-H48r40XUZBdczeEwlKl8n' +
          'PQxDou_r_83HzSCMbVwY');
    });
  });


  it('should read jwt encripted with the right hash', function() {
    var jwtToken = 'eyJhbGciOiJkaXIiLCJlbmMiOi' +
        'JBMTI4Q0JDLUhTMjU2Iiwia2lkIjoieW91ci1' +
        'jbGllbnQtaWQifQ..c-xfuN2UeyOMuMBey-Rr' +
        'rg.OWATzLb6knY3WklIIz3CoXJsgnC9MSC-sV' +
        '3EKBl5ffE8Yqtg2_oUElZUgku08fR2p4IZwOT' +
        'EmGf982vO7lIHN_YlnF-2tAfLrDZSr1Lb4ETL' +
        'G-2pfKkgx3iGoL7TqA2liDIfFWeoQpXku-dRc' +
        'beJuVsrTCbyvMvqcBbcZ3ETmTytlUjhmmwGRL' +
        'xBlsGt3V9le0cB_p4KiWzYlYr0Jj-7gzLmL4Y' +
        'XQqN-6KrjtuC6IXwCt-8ba_lyv0AmtqxQq-UC' +
        'I2adk-ZGYyAJi7lv4jAG_g.6TBHBz6uzJ3FS8' +
        '7KFf0x6g';

    var hashKey = '796f75722d7365637265742d6b657923';
    var encKey = '796f75722d7365637265742d6b657923';

    var clock = sinon.useFakeTimers(0, 'Date');
    clock.tick((1375267462041 + 1) * 1000);

    jwtUtils.readJWTEncrypted(jwtToken, encKey, hashKey, function(err, token) {
      expect(err).not.to.exist;
      expect(token).to.exist;
      expect(token.payload.iss).to.equal('tdaf-accounts');
      clock.restore();
    });
  });

  it('should return an algorithm error ', function() {
    var jwtToken = 'eyJhbGciOiJkaXIiLCJlbmMiOi' +
        'JVTktOT1dOLUhTMjU2Iiwia2lkIjoieW91ci1' +
        'jbGllbnQtaWQifQ..c-xfuN2UeyOMuMBey-Rr' +
        'rg.OWATzLb6knY3WklIIz3CoXJsgnC9MSC-sV' +
        '3EKBl5ffE8Yqtg2_oUElZUgku08fR2p4IZwOT' +
        'EmGf982vO7lIHN_YlnF-2tAfLrDZSr1Lb4ETL' +
        'G-2pfKkgx3iGoL7TqA2liDIfFWeoQpXku-dRc' +
        'beJuVsrTCbyvMvqcBbcZ3ETmTytlUjhmmwGRL' +
        'xBlsGt3V9le0cB_p4KiWzYlYr0Jj-7gzLmL4Y' +
        'XQqN-6KrjtuC6IXwCt-8ba_lyv0AmtqxQq-UC' +
        'I2adk-ZGYyAJi7lv4jAG_g.6TBHBz6uzJ3FS8' +
        '7KFf0x6g';

    var hashKey = '796f75722d7365637265742d6b657923';
    var encKey = '796f75722d7365637265742d6b657923';

    jwtUtils.readJWTEncrypted(jwtToken, encKey, hashKey, function(err, token) {
      expect(err).to.exist;
      expect(token).to.not.exist;
      expect(err).to.be.apiError(errors.ALGORITHM_NOT_SUPPORTED());
    });
  });

  it('should not read a jwt from future', function() {
    var jwtToken = 'eyJhbGciOiJkaXIiLCJlbmMiOi' +
        'JBMTI4Q0JDLUhTMjU2Iiwia2lkIjoieW91ci1' +
        'jbGllbnQtaWQifQ..c-xfuN2UeyOMuMBey-Rr' +
        'rg.OWATzLb6knY3WklIIz3CoXJsgnC9MSC-sV' +
        '3EKBl5ffE8Yqtg2_oUElZUgku08fR2p4IZwOT' +
        'EmGf982vO7lIHN_YlnF-2tAfLrDZSr1Lb4ETL' +
        'G-2pfKkgx3iGoL7TqA2liDIfFWeoQpXku-dRc' +
        'beJuVsrTCbyvMvqcBbcZ3ETmTytlUjhmmwGRL' +
        'xBlsGt3V9le0cB_p4KiWzYlYr0Jj-7gzLmL4Y' +
        'XQqN-6KrjtuC6IXwCt-8ba_lyv0AmtqxQq-UC' +
        'I2adk-ZGYyAJi7lv4jAG_g.6TBHBz6uzJ3FS8' +
        '7KFf0x6g';

    var hashKey = '796f75722d7365637265742d6b657923';
    var encKey = '796f75722d7365637265742d6b657923';

    var clock = sinon.useFakeTimers(0, 'Date');
    clock.tick((1375267462041 - 5) * 1000);

    jwtUtils.readJWTEncrypted(jwtToken, encKey, hashKey, function(err, token) {
      expect(err).to.be.apiError(errors.FUTURE_JWT());
      expect(token).to.not.exist;
      clock.restore();
    });
  });

  it('should return an error when jwt encrypted has a bad hash', function() {
    var jwtToken = 'eyJhbGciOiJkaXIiLCJlbmMiOi' +
        'JBMTI4Q0JDLUhTMjU2Iiwia2lkIjoieW91ci1jb' +
        'GllbnQtaWQifQ==..c-xfuN2UeyOMuMBey-Rrrg' +
        '==.DhtMD5203CkjQNVu4P0-W3q19ZRq5JJbkrh4' +
        'uzg8MLq68a6CRgfKbhV6QFNOoeydzCfzoQ8nA4z' +
        'gLf40JX_DuP4QAKDyyLK-lczyOYVhIp7KwpAFqW' +
        'WOIjoDRi-5xIMEV9h8RzHuD-moMKHWepDnaNtAy' +
        'L1X6LtNVEpux3YldduaHoVNkTTGtLWBpjICZwG0' +
        'QoFwWn3mU9O6gu8pHbSm2unrLEENqHqUBKpO276' +
        'G8huJnU0-mhgP2MV2CdUgEAYC__WDh7KMDaDZXF' +
        'UW5ZNBsA==.11111cb2qTCGTyaKDmDA==';

    var hashKey = '796f75722d7365637265742d6b657923';
    var encKey = '796f75722d7365637265742d6b657923';

    jwtUtils.readJWTEncrypted(jwtToken, encKey, hashKey, function(err, token) {
      expect(err).to.be.apiError(errors.DECRYPTION_ERROR());
      expect(token).not.to.exist;
    });
  });

  it('should return an error when jwt encrypted does not have hash', function() {
    var jwtToken = 'eyJhbGciOiJkaXIiLCJlbmMiOi' +
        'JBMTI4Q0JDLUhTMjU2Iiwia2lkIjoieW91ci1jb' +
        'GllbnQtaWQifQ==..c-xfuN2UeyOMuMBey-Rrrg' +
        '==.DhtMD5203CkjQNVu4P0-W3q19ZRq5JJbkrh4' +
        'uzg8MLq68a6CRgfKbhV6QFNOoeydzCfzoQ8nA4z' +
        'gLf40JX_DuP4QAKDyyLK-lczyOYVhIp7KwpAFqW' +
        'WOIjoDRi-5xIMEV9h8RzHuD-moMKHWepDnaNtAy' +
        'L1X6LtNVEpux3YldduaHoVNkTTGtLWBpjICZwG0' +
        'QoFwWn3mU9O6gu8pHbSm2unrLEENqHqUBKpO276' +
        'G8huJnU0-mhgP2MV2CdUgEAYC__WDh7KMDaDZXF' +
        'UW5ZNBsA==';

    var hashKey = '796f75722d7365637265742d6b657923';
    var encKey = '796f75722d7365637265742d6b657923';

    jwtUtils.readJWTEncrypted(jwtToken, encKey, hashKey, function(err, token) {
      expect(err).to.be.apiError(errors.SEGMENTS_NUMBER_ERROR(4));
      expect(token).not.to.exist;
    });
  });

  it('return an error when jwt encrypted does not have the fourth segment', function() {
    var jwtToken = 'eyJhbGciOiJkaXIiLCJlbmMiOi' +
        'JBMTI4Q0JDLUhTMjU2Iiwia2lkIjoieW91ci1' +
        'jbGllbnQtaWQifQ....6TBHBz6uzJ3FS8' +
        '7KFf0x6g';

    var hashKey = '796f75722d7365637265742d6b657923';
    var encKey = '796f75722d7365637265742d6b657923';

    jwtUtils.readJWTEncrypted(jwtToken, encKey, hashKey, function(err, token) {
      expect(err).to.be.apiError(errors.INVALID_FOURTH_SEGMENT());
      expect(token).not.to.exist;
    });
  });

  it('should encrypt a JWT (default A256CBC-HS256)', function(done) {
    var payload = {
          hola: 'caracola'
        },
        kid = 'your-client-id',
        key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923',
        hashKey = '796f75722d7365637265742d6b657923';

    jwtUtils.buildJWTEncrypted(payload, {kid: kid}, key, hashKey, function(err, jwt) {
      expect(jwt).to.be.ok;
      jwtUtils.readJWTEncrypted(jwt, key, hashKey, function(err, token) {
        expect(err).to.not.exist;
        expect(token.payload).to.be.deep.equal(payload);
        done(err);
      });
    });
  });

  it('should encrypt a JWT with A128CBC-HS256', function(done) {
    var payload = {
          hola: 'caracola'
        },
        kid = 'your-client-id',
        key = '796f75722d7365637265742d6b657923',
        hashKey = '796f75722d7365637265742d6b657923';

    jwtUtils.buildJWTEncrypted(payload, {kid: kid, enc: 'A128CBC-HS256'}, key, hashKey, function(err, jwt) {
      expect(jwt).to.be.ok;
      var segments = jwt.split('.');
      expect(segments[1]).to.be.equal('');
      var authTagBuff = new Buffer(segments[4], 'base64');
      expect(authTagBuff.length).to.be.equal(16);
      expect(err).to.not.exist;
      jwtUtils.readJWTEncrypted(jwt, key, hashKey, function(err, token) {
        expect(err).to.not.exist;
        expect(token.payload).to.be.deep.equal(payload);
        done(err);
      });
    });
  });

  it('should return a missing header error when it tries to build a jwtEnc', function() {
    var payload = {
          hola: 'caracola'
        },
        key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923',
        hashKey = '796f75722d7365637265742d6b657923';

    jwtUtils.buildJWTEncrypted(payload, null, key, hashKey, function(err, jwt) {
      expect(err).to.be.apiError(errors.MISSING_REQUIRED_HEADER());
      expect(jwt).not.to.exist;
    });
  });

  it('should return a missing kid error when it tries to build a jwtEnc', function() {
    var payload = {
          hola: 'caracola'
        },
        key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923',
        hashKey = '796f75722d7365637265742d6b657923';

    jwtUtils.buildJWTEncrypted(payload, {}, key, hashKey, function(err, jwt) {
      expect(err).to.be.apiError(errors.MISSING_REQUIRED_KID());
      expect(jwt).not.to.exist;
    });
  });

  it('should return a algorithm not supported error when it tries to build a jwtEnc', function() {
    var payload = {
          hola: 'caracola'
        },
        key = '796f75722d7365637265742d6b657923',
        hashKey = '796f75722d7365637265742d6b657923';

    jwtUtils.buildJWTEncrypted(payload, {enc: 'UNKNOWN', kid: 'kid'}, key, hashKey, function(err, jwt) {
      expect(err).to.be.apiError(errors.ALGORITHM_NOT_SUPPORTED());
      expect(jwt).not.to.exist;
    });
  });

  it('should add iat to payload if not present', function(done) {
    var payload = {
          hola: 'caracola'
        },
        kid = 'your-client-id',
        key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923',
        hashKey = '796f75722d7365637265742d6b657923';

    var seconds = 10;
    var clock = sinon.useFakeTimers(seconds * 1000);

    jwtUtils.buildJWTEncrypted(payload, {kid: kid}, key, hashKey, function(err, jwt) {
      expect(err).to.not.exist;
      jwtUtils.readJWTEncrypted(jwt, key, hashKey, function(err, token) {
        expect(err).to.not.exist;
        expect(token.payload).to.have.property('iat');
        expect(token.payload.iat).to.equal(seconds);
        done(err);
      });
    });
  });

  it('should not add iat to payload if already present', function(done) {
    var payload = {
          hola: 'caracola',
          iat: 1
        },
        kid = 'your-client-id',
        key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923',
        hashKey = '796f75722d7365637265742d6b657923';

    jwtUtils.buildJWTEncrypted(payload, {kid: kid}, key, hashKey, function(err, jwt) {
      var clock = sinon.useFakeTimers(payload.iat * 1000);
      expect(err).to.not.exist;
      jwtUtils.readJWTEncrypted(jwt, key, hashKey, function(err, token) {
        expect(err).to.not.exist;
        expect(token.payload).to.have.property('iat');
        expect(token.payload.iat).to.equal(payload.iat);
        done(err);
      });
    });
  });

  it('should be able to maintain overriden fields', function(done) {
    var payload = {
          hola: 'caracola',
          iss: 'loquillo',
          iat: 123,
          jti: 'troglodita'
        },
        kid = 'your-client-id',
        key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923',
        hashKey = '796f75722d7365637265742d6b657923';


    jwtUtils.buildJWTEncrypted(payload, {kid: kid}, key, hashKey, function(err, jwt) {
      expect(err).to.not.exist;
      var clock = sinon.useFakeTimers(0, 'Date');
      clock.tick(payload.iat * 1000);
      jwtUtils.readJWTEncrypted(jwt, key, hashKey, function(err, token) {
        clock.restore();
        expect(err).to.not.exist;
        expect(token.payload).to.have.property('jti', 'troglodita');
        expect(token.payload).to.have.property('iss', 'loquillo');
        expect(token.payload).to.have.property('iat', payload.iat);
        done(err);
      });
    });
  });

  it('should fail to decrypt a JWT with other hashKey', function(done) {
    var payload = {
          hola: 'caracola'
        },
        kid = 'your-client-id',
        key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923',
        hashKey = '796f75722d7365637265742d6b657923',
        invalidHashKey = '11111111111111111111111111111111';

    jwtUtils.buildJWTEncrypted(payload, {kid: kid}, key, hashKey, function(err, jwt) {
      expect(err).to.not.exist;
      jwtUtils.readJWTEncrypted(jwt, key, invalidHashKey, function(err, token) {
        expect(err).to.be.apiError(errors.DECRYPTION_ERROR());
        expect(token).to.not.exist;
        done();
      });
    });
  });

  it('should fail decrypting a JWT with other key', function(done) {
    var payload = {
          hola: 'caracola'
        },
        kid = 'your-client-id',
        hashKey = '796f75722d7365637265742d6b657923',
        key1 = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923',
        key2 = '1111111111111111111111111111111111111111111111111111111111111111';

    jwtUtils.buildJWTEncrypted(payload, {kid: kid}, key1, hashKey, function(err, jwt) {
      expect(err).to.not.exist;
      jwtUtils.readJWTEncrypted(jwt, key2, hashKey, function(err, token) {
        expect(err).to.be.apiError(errors.DECRYPTION_ERROR());
        expect(token).to.not.exist;
        done();
      });
    });
  });

  it('should fail encrypting a JWT with an invalid key', function(done) {
    var payload = {
          hola: 'caracola'
        },
        kid = 'your-client-id',
        hashKey = '796f75722d7365637265742d6b657923',
        invalidKey1 = '1', // too short
        invalidKey2 = '11111111111111111111111111111111333333'; // too long

    jwtUtils.buildJWTEncrypted(payload, {kid: kid}, invalidKey1, hashKey, function(err) {
      expect(err).to.be.apiError(errors.ENCRYPTION_ERROR());
      jwtUtils.buildJWTEncrypted(payload, {kid: kid}, invalidKey2, hashKey, function(err) {
        expect(err).to.be.apiError(errors.ENCRYPTION_ERROR());
        done();
      });
    });
  });

  it('should fail when the JWT is expired', function(done) {
    var expiration = 10;
    var jwtUtilsMod = jwt({expiration: expiration});

    var payload = {
          hola: 'caracola'
        },
        kid = 'your-client-id',
        key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923',
        hashKey = '796f75722d7365637265742d6b657923';

    jwtUtilsMod.buildJWTEncrypted(payload, {kid: kid}, key, hashKey, function(err, jwt) {
      expect(err).to.not.exist;
      var clock = sinon.useFakeTimers(new Date().getTime());
      clock.tick((expiration + 1) * 1000);
      jwtUtils.readJWTEncrypted(jwt, key, hashKey, function(err, token) {
        expect(err).to.exist;
        expect(err).to.be.apiError(errors.EXPIRED_JWT());
        clock.restore();
        done();
      });
    });
  });

  it('should read an unencrypted token', function() {
    var jwtToken = 'eyJhbGciOiJIUzI1NiIsImtpZC' +
        'I6InlvdXItY2xpZW50LWlkIn0.eyJyZXF1ZXN0I' +
        'jp7ImNvbnRpbnVlIjoiaHR0cDovL3lvdXItc2Vy' +
        'dmljZS5jb20vY29udGludWUtaGFuZGxlciIsImZ' +
        'vY2VMb2dpbiI6dHJ1ZX0sImF1ZCI6WyJ0ZGFmLW' +
        'FjY291bnRzIl0sImlzcyI6InNvbWV0aGluZy10b' +
        'y1oZWxwLXRyYWNlIiwianRpIjoiYmU0ZWE5N2Ut' +
        'YmFkOC00NWQ2LWEwNjktOTI4YjUzNDQxZjRjIiw' +
        'iaWF0IjoxMzc0MDc4ODcxfQ.rxS6hoB1xP_a13J' +
        'rEFqY7RdzY3pxko-UDfZZ3QFqnEI';

    var hashKey = '796f75722d7365637265742d6b657923';
    var tokenIat = 1374078871;

    var clock = sinon.useFakeTimers(0, 'Date');
    clock.tick((tokenIat + 1) * 1000);

    jwtUtils.readJWT(jwtToken, hashKey, function(err, token) {
      expect(err).not.to.exist;
      expect(token.payload).to.exist;

      expect(token.payload).to.be.deep.equal({
        'request': {
          'continue': 'http://your-service.com/continue-handler',
          'foceLogin': true
        },
        'aud': ['tdaf-accounts'],
        'iss': 'something-to-help-trace',
        'jti': 'be4ea97e-bad8-45d6-a069-928b53441f4c',
        'iat': tokenIat
      });
    });
  });

  it('should fail to read an unencrypted token with invalid number of segments', function() {
    var jwtToken = 'eyJhbGciOiJIUzI1NiJ9.eyJpc' +
        '3MiOiIiLCJqdGkiOiIiLCJpYXQiOjEzNzQwNzg4' +
        'NzF9';

    var hashKey = '11111111111111111111111111111111';
    jwtUtils.readJWT(jwtToken, hashKey, function(err, token) {
      expect(err).to.be.apiError(errors.SEGMENTS_NUMBER_ERROR(2));
      expect(token).not.to.exist;
    });
  });

  it('should fail to read an unencrypted token without a valid algorithm', function() {
    var jwtToken = 'eyJhbGciOiJIUzI1NyIsICJraWQiOiJteUtpZCJ9.eyJpc' +
        '3MiOiIiLCJqdGkiOiIiLCJpYXQiOjEzNzQwNzg4' +
        'NzF9.khagsjdgjas';

    var hashKey = '11111111111111111111111111111111';
    jwtUtils.readJWT(jwtToken, hashKey, function(err, token) {
      expect(err).to.be.apiError(errors.ALGORITHM_NOT_SUPPORTED());
      expect(token).not.to.exist;
    });
  });

  it('should fail to read an unencrypted token without a valid key or hash', function() {
    var jwtToken = 'eyJhbGciOiJIUzI1NiIsICJraWQiOiJteUtpZCJ9.eyJpc' +
        '3MiOiIiLCJqdGkiOiIiLCJpYXQiOjEzNzQwNzg4' +
        'NzF9.khagsjdgjas';

    var hashKey = '11111111111111111111111111111111';
    jwtUtils.readJWT(jwtToken, hashKey, function(err, token) {
      expect(err).to.be.apiError(errors.WRONG_TOKEN_SIGNATURE());
      expect(token).not.to.exist;
    });
  });


  it('should read the header of an encrypted JWT', function() {
    var payload = {},
        kid = 'your-client-id',
        key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923',
        hashKey = '796f75722d7365637265742d6b657923';

    jwtUtils.buildJWTEncrypted(payload, {kid: kid}, key, hashKey, function(err, jwt) {
      jwtUtils.readJWTHeader(jwt, function(err, header) {
        expect(header).to.have.property('alg');
        expect(header.kid).to.equal(kid);
      });
    });
  });

  it('should read the header of an unencrypted JWT', function() {
    var payload = {},
        kid = 'your-client-id',
        hashKey = '796f75722d7365637265742d6b657923';

    jwtUtils.buildJWT(payload, {kid: kid}, hashKey, function(err, jwt) {
      jwtUtils.readJWTHeader(jwt, function(err, header) {
        expect(header).to.have.property('alg');
        expect(header.kid).to.equal(kid);
      });
    });
  });

  it('should fail while reading the header of an invalid JWT', function() {
    var jwtToken = 'wrongheader.wrongpayload.wrongsignature';
    jwtUtils.readJWTHeader(jwtToken, function(err, header) {
      expect(err).to.be.apiError(errors.INVALID_HEADER());
      expect(header).not.to.exist;
    });
  });

  it('should generate and read a JWT signed using RS256, privKey 1024', function() {
    var payload = {
          myField: 'myValue'
        },
        header = {
            kid: 'kid',
            alg: 'RS256'
        };

    var privateKey = fs.readFileSync(__dirname + '/sampleKeys/privateKey.pem');
    var publicKey = fs.readFileSync(__dirname + '/sampleKeys/publicKey.pem');
    jwtUtils.buildJWT(payload, header, privateKey, function(err, result) {
      expect(err).to.not.exist;
      expect(result).to.exist;
      jwtUtils.readJWT(result, publicKey, function(err, decodedResult) {
        expect(err).to.not.exist;
        expect(decodedResult).to.exist;
        expect(decodedResult.header).to.exist;
        expect(decodedResult.header.alg).to.be.equal('RS256');
        expect(decodedResult.header.kid).to.be.equal('kid');
        expect(decodedResult.payload).to.exist;
        expect(decodedResult.payload.iat).to.exist;
        expect(decodedResult.payload.myField).to.be.equal('myValue');
      });
    });
  });

  it('should generate and read a JWT signed using RS256, privKey 512', function() {
    var payload = {
          myField: 'myValue'
        },
        header = {
          kid: 'kid',
          alg: 'RS256'
        };
    var privateKey = fs.readFileSync(__dirname + '/sampleKeys/privateKey2.pem');
    var publicKey = fs.readFileSync(__dirname + '/sampleKeys/publicKey2.pem');
    jwtUtils.buildJWT(payload, header, privateKey, function(err, result) {
      expect(err).to.not.exist;
      expect(result).to.exist;
      jwtUtils.readJWT(result, publicKey, function(err, decodedResult) {
        expect(err).to.not.exist;
        expect(decodedResult).to.exist;
        expect(decodedResult.header).to.exist;
        expect(decodedResult.header.alg).to.be.equal('RS256');
        expect(decodedResult.header.kid).to.be.equal('kid');
        expect(decodedResult.payload).to.exist;
        expect(decodedResult.payload.iat).to.exist;
        expect(decodedResult.payload.myField).to.be.equal('myValue');
      });
    });
  });

  it('should return a read error of a JWT signed by privateKey and verified with publicKey2', function() {
    var payload = {
          myField: 'myValue'
        },
        header = {
          kid: 'kid',
          alg: 'RS256'
        };
    var privateKey = fs.readFileSync(__dirname + '/sampleKeys/privateKey.pem');
    var publicKey = fs.readFileSync(__dirname + '/sampleKeys/publicKey2.pem');
    jwtUtils.buildJWT(payload, header, privateKey, function(err, result) {
      expect(err).to.not.exist;
      expect(result).to.exist;
      jwtUtils.readJWT(result, publicKey, function(err, decodedResult) {
        expect(err).to.exist;
        expect(err).to.be.apiError(errors.WRONG_TOKEN_SIGNATURE());
        expect(decodedResult).to.not.exist;
      });
    });
  });

  it('should encrypt and decrypt with A256CBC-HS512', function() {
    var payload = {
      status: 'ok'
    };
    var header = {
      alg: 'dir',
      enc: 'A256CBC-HS512',
      corr: 'corr',
      kid: 'kid'
    };
    var key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923';
    jwtUtils.buildJWTEncrypted(payload, header, key, key, function(error, jwt) {
      expect(jwt).to.exist;
      var segments = jwt.split('.');
      expect(segments[1]).to.be.equal('');
      var authTagBuff = new Buffer(segments[4], 'base64');
      expect(authTagBuff.length).to.be.equal(32);
      expect(error).to.not.exist;
      jwtUtils.readJWTEncrypted(jwt, key, key, function(err, token) {
        expect(token).to.exist;
        expect(token.header).to.exist;
        expect(token.header.corr).to.be.equal('corr');
        expect(token.header.kid).to.be.equal('kid');
        expect(token.header.alg).to.be.equal('dir');
        expect(token.header.enc).to.be.equal('A256CBC-HS512');
        expect(token.payload).to.exist;
        expect(token.payload.iat).to.exist;
        expect(token.payload.status).to.be.equal('ok');
        expect(err).to.not.exist;
      });
    });
  });

  it('should encrypt and decrypt with A256CBC-HS512 with utf8 characters in payload', function() {
    var payload = {
      status: 'ok',
      testStr: 'áéíóúñçÇÁÉÍÓÚ'
    };
    var header = {
      alg: 'dir',
      enc: 'A256CBC-HS512',
      corr: 'corr',
      kid: 'kid'
    };
    var key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923';
    jwtUtils.buildJWTEncrypted(payload, header, key, key, function(error, jwt) {
      expect(jwt).to.exist;
      var segments = jwt.split('.');
      expect(segments[1]).to.be.equal('');
      var authTagBuff = new Buffer(segments[4], 'base64');
      expect(authTagBuff.length).to.be.equal(32);
      expect(error).to.not.exist;
      jwtUtils.readJWTEncrypted(jwt, key, key, function(err, token) {
        expect(token).to.exist;
        expect(token.header).to.exist;
        expect(token.header.corr).to.be.equal('corr');
        expect(token.header.kid).to.be.equal('kid');
        expect(token.header.alg).to.be.equal('dir');
        expect(token.header.enc).to.be.equal('A256CBC-HS512');
        expect(token.payload).to.exist;
        expect(token.payload.iat).to.exist;
        expect(token.payload.status).to.be.equal('ok');
        expect(token.payload.testStr).to.be.equal(payload.testStr);
        expect(err).to.not.exist;
      });
    });
  });

  it('should encrypt and decrypt with A256CBC-HS512 with utf8 characters in payload and longer length than encryption' +
      ' block', function() {
    var payload = {
      status: 'ok',
      testStr: 'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ'
    };
    var header = {
      alg: 'dir',
      enc: 'A256CBC-HS512',
      corr: 'corr',
      kid: 'kid'
    };
    var key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923';
    jwtUtils.buildJWTEncrypted(payload, header, key, key, function(error, jwt) {
      expect(jwt).to.exist;
      var segments = jwt.split('.');
      expect(segments[1]).to.be.equal('');
      var authTagBuff = new Buffer(segments[4], 'base64');
      expect(authTagBuff.length).to.be.equal(32);
      expect(error).to.not.exist;
      jwtUtils.readJWTEncrypted(jwt, key, key, function(err, token) {
        expect(token).to.exist;
        expect(token.header).to.exist;
        expect(token.header.corr).to.be.equal('corr');
        expect(token.header.kid).to.be.equal('kid');
        expect(token.header.alg).to.be.equal('dir');
        expect(token.header.enc).to.be.equal('A256CBC-HS512');
        expect(token.payload).to.exist;
        expect(token.payload.iat).to.exist;
        expect(token.payload.status).to.be.equal('ok');
        expect(token.payload.testStr).to.be.equal(payload.testStr);
        expect(err).to.not.exist;
      });
    });
  });

  it('should encrypt and decrypt with A256CBC-HS512 with utf8 characters in payload and longer length than encryption' +
      ' block with an ascii character in the beginning of the string', function() {
    var payload = {
      status: 'ok',
      testStr: 'aáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ' +
          'áéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚáéíóúñçÇÁÉÍÓÚ'
    };
    var header = {
      alg: 'dir',
      enc: 'A256CBC-HS512',
      corr: 'corr',
      kid: 'kid'
    };
    var key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923';
    jwtUtils.buildJWTEncrypted(payload, header, key, key, function(error, jwt) {
      expect(jwt).to.exist;
      var segments = jwt.split('.');
      expect(segments[1]).to.be.equal('');
      var authTagBuff = new Buffer(segments[4], 'base64');
      expect(authTagBuff.length).to.be.equal(32);
      expect(error).to.not.exist;
      jwtUtils.readJWTEncrypted(jwt, key, key, function(err, token) {
        expect(token).to.exist;
        expect(token.header).to.exist;
        expect(token.header.corr).to.be.equal('corr');
        expect(token.header.kid).to.be.equal('kid');
        expect(token.header.alg).to.be.equal('dir');
        expect(token.header.enc).to.be.equal('A256CBC-HS512');
        expect(token.payload).to.exist;
        expect(token.payload.iat).to.exist;
        expect(token.payload.status).to.be.equal('ok');
        expect(token.payload.testStr).to.be.equal(payload.testStr);
        expect(err).to.not.exist;
      });
    });
  });

  it('should fail when it try to encrypt with an unknown hash algorithm', function() {
    var payload = {
      status: 'ok'
    };
    var header = {
      alg: 'dir',
      enc: 'A256CBC-HS4645',
      corr: 'corr',
      kid: 'kid'
    };
    var key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923';
    jwtUtils.buildJWTEncrypted(payload, header, key, key, function(err, jwt) {
      expect(jwt).to.not.exist;
      expect(err).to.be.apiError(errors.ALGORITHM_NOT_SUPPORTED());
      expect(err.message).to.be.equal('Algorithm not supported. Invalid hash algorithm: HS4645');
    });
  });

  it('should fail when it try to decrypt with an unknown hash algorithm', function() {
    var jwt = 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTMjQ1NiIsImNvcnI' +
        'iOiJjb3JyIiwia2lkIjoia2lkIn0=..i5DUiRZiE7nudmAaNqbkow.eMSIEpr' +
        '5Brj0Wc8Acn7QzcGM-_5ALrKUVy9xLUobIFokMBw9RT5wKXmQ_AXWTnqS.Ce3' +
        'jmzDaztKcav0sFd2cQw';
    var key = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923';
    jwtUtils.readJWTEncrypted(jwt, key, key, function(err, token) {
      expect(token).to.not.exist;
      expect(err).to.be.apiError(errors.ALGORITHM_NOT_SUPPORTED());
      expect(err.message).to.be.equal('Algorithm not supported. Invalid hash algorithm: HS2456');

    });
  });

  it('should fail when client expired the jwt without taking into account the exp field', function() {
    var jwtToken = 'eyJraWQiOiJraWQiLCJhbGciOiJkaXIiLCJlbmMiOiJBMjU' +
        '2Q0JDLUhTNTEyIiwiY29yciI6ImNvcnIifQ..Xuaus8N7yqmojQFFFNgxL' +
        'g.UCM5odV53W9NEaVvee7fCKb31B1C7wedJn02vapNOf2v3-dmKDaZxt2G' +
        'nIDYK-TQ-XkiziRkRtZkjABFRNHPYw.FFduxvzrjIhWu8dQ3MMOVH11-tE' +
        'BgE6955c4M9EO3fk';

    var hashKey = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923';
    var encKey = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923';

    var clock = sinon.useFakeTimers(0, 'Date');
    clock.tick((1443688542000 + 1) * 1000);

    var jwtUtilsMod = jwt({expiration: 1});

    jwtUtilsMod.readJWTEncrypted(jwtToken, encKey, hashKey, function(err, token) {
      expect(err).to.exist;
      expect(err.name).to.be.equal('NO_FRESH_JWT');
      clock.restore();
    });
  });

  it('should not check expiry with config.expiration set to 0', function() {
    var jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A';
    var hashKey = '796f75722d3235362d6269742d736563726574';

    var jwtUtilsMod = jwt({expiration: 0});

    jwtUtilsMod.readJWT(jwtToken, hashKey, function(err, token) {
      expect(err).to.not.exist;
    });
  });

  it('should check expiry with config.expiration set to a value other than 0', function() {
    var jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A';
    var hashKey = '796f75722d3235362d6269742d736563726574';

    var jwtUtilsMod = jwt({expiration: 1});

    jwtUtilsMod.readJWT(jwtToken, hashKey, function(err, token) {
      expect(err).to.exist;
    });
  });

  it('should check iat and exp if present, even with config.expiration set to 0', function() {
    var jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIwLCJleHAiOjE1MTYyMzkwMjF9.H_PgIMtvx7m9-vwIc3JBL6FBUEowa9MSYg7bx-BPmBQ';
    var hashKey = '796f75722d3235362d6269742d736563726574';

    var clock = sinon.useFakeTimers(0, 'Date');
    clock.tick((1516239022000 + 1) * 1000);

    var jwtUtilsMod = jwt({expiration: 0});

    jwtUtilsMod.readJWT(jwtToken, hashKey, function(err, token) {
      expect(err).to.exist;
      clock.restore();
    });
  });

});
