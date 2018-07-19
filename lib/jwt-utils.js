/**
 * @license
 * Copyright 2015 Telefónica Investigación y Desarrollo, S.A.U
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

var crypto = require('crypto');
var debugLib = require('debug'),
    _ = require('underscore'),
    jwa = require('jwa');
var errors = require('./errors');

var debug = debugLib('tef:base:jwtUtils');

var hashAlgorithms = {
  HS256: 'sha256',
  RS256: 'rsa-sha256',
  HS512: 'sha512'
};

var cipherMap = {
  A128CBC: 'aes-128-cbc',
  A256CBC: 'aes-256-cbc'
};

var authenticationTagBits = {
  'sha256': 16,
  'sha512': 32
};

/*jshint -W069 */
/*jshint -W072*/
/*jshint -W098*/
/*jshint -W117*/
var DEFAULT_CONFIG = {
  //Number of seconds to consider a jwt expired
  expiration: 600,
  futureTolerance: 4
};

/**
 * The exported API
 * @type {*}
 * @return {Object}
 */
module.exports = function(configuration) {

  var config = {};

  function base64urlEscape(str) {
    return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  function base64urlUnescape(str) {
    str += new Array(5 - str.length % 4).join('=');
    return str.replace(/\-/g, '+').replace(/_/g, '/');
  }

  function base64urlEncode(str) {
    return base64urlEscape(new Buffer(str).toString('base64'));
  }

  function base64urlDecode(str) {
    return new Buffer(base64urlUnescape(str), 'base64');
  }

  function encodeBase64url(base64) {
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
  }

  function convertSlowBufToBuf(slowBuffer) {
    var buffer = new Buffer(slowBuffer.length);
    slowBuffer.copy(buffer);
    return buffer;
  }

  function readJWTHeader(base64header) {
    var headerStr = base64urlDecode(base64header);
    var header = JSON.parse(headerStr);
    return header;
  }

  function getEncryptionAndHashAlgoritms(encHeaderValue) {
    var algs = encHeaderValue.split('-');
    var cipherAlgorithm = cipherMap[algs[0]];
    var hashAlgorithm = hashAlgorithms[algs[1]];

    if (!cipherAlgorithm) {
      throw errors.ALGORITHM_NOT_SUPPORTED('Invalid encryption algorithm: ' + algs[0]);
    }

    if (!hashAlgorithm) {
      throw errors.ALGORITHM_NOT_SUPPORTED('Invalid hash algorithm: ' + algs[1]);
    }
    return {
      cipherAlgorithm: cipherAlgorithm,
      hashAlgorithm: hashAlgorithm
    };
  }

  function encodeJWT(payload, header, key) {
    if (!key) {
      throw errors.MISSING_REQUIRED_KEY();
    }

    if (!hashAlgorithms[header.alg]) {
      throw errors.ALGORITHM_NOT_SUPPORTED();
    }

    // header, typ is fixed value.
    if (!header.kid) {
      throw errors.MISSING_REQUIRED_KID();
    }

    // create segments, all segment should be base64 string
    var segments = [];
    segments.push(base64urlEncode(JSON.stringify(header)));
    segments.push(base64urlEncode(JSON.stringify(payload)));
    var signer = jwa(header.alg);
    //If we use RS256, the key is the private Key
    if (header.alg.indexOf('HS') === 0) {
      key = new Buffer(key, 'hex');
    }
    segments.push(signer.sign(segments.join('.'), key));

    return segments.join('.');
  }

  function decodeJWT(token, key) {
    var segments = token.split('.');
    if (segments.length !== 3) {
      throw errors.SEGMENTS_NUMBER_ERROR(segments.length);
    }

    var header = readJWTHeader(segments[0]);

    var algorithm = header.alg || 'HS256';

    if (!hashAlgorithms[header.alg]) {
      throw errors.ALGORITHM_NOT_SUPPORTED();
    }

    var signer = jwa(algorithm);
    if (algorithm.indexOf('HS') === 0) {
      key = new Buffer(key, 'hex');
    }
    if (!signer.verify(segments[0] + '.' + segments[1], segments[2], key)) {
      throw errors.WRONG_TOKEN_SIGNATURE();
    }

    var payloadStr = base64urlDecode(segments[1]);

    return {
      header: header,
      payload: JSON.parse(payloadStr)
    };
  }

  function decryptJWT(token, encKey, hashKey) {
    var segments = token.split('.');
    if (segments.length !== 5) {
      throw errors.SEGMENTS_NUMBER_ERROR(segments.length);
    }

    var header = readJWTHeader(segments[0]);

    if (!header.kid) {
      throw errors.MISSING_REQUIRED_KID();
    }

    var algorithms = getEncryptionAndHashAlgoritms(header.enc);

    var initializationVector = null;
    if (segments[2]) {
      initializationVector = base64urlDecode(segments[2]);
    }

    var cypherText = null;
    if (segments[3] === null || segments[3] === '') {
      throw errors.INVALID_FOURTH_SEGMENT();
    } else {
      cypherText = base64urlDecode(segments[3]);
    }

    var origAuthenticationTag = null;
    if (segments[4]) {
      origAuthenticationTag = segments[4];
    }

    var encKeyBuffer = new Buffer(encKey, 'hex');
    var result, hashBuf;
    try {
      var decipher = crypto.createDecipheriv(algorithms.cipherAlgorithm, encKeyBuffer, initializationVector);

      decipher.setAutoPadding(true);

      var mainBody = decipher.update(cypherText);
      var endBody = decipher.final();
      result = Buffer.concat([convertSlowBufToBuf(mainBody), convertSlowBufToBuf(endBody)]).toString();

      var b64Header = new Buffer(segments[0]);
      var iv = new Buffer(initializationVector);
      var encryptedBody = new Buffer(cypherText);

      // create al vector
      var al = new Buffer(4);
      al.writeInt32BE(b64Header.length * 8, 0);

      var buf4Clear = new Buffer(4);
      buf4Clear.fill(0);
      var alResult = Buffer.concat([buf4Clear, al]);

      var authTag = new Buffer(Buffer.concat([b64Header, iv, encryptedBody, alResult]));

      var hashKeyBuffer = new Buffer(hashKey, 'hex');
      var authTagHash = crypto.createHmac(algorithms.hashAlgorithm, hashKeyBuffer).update(authTag).digest();

      var authTagHashBuf = convertSlowBufToBuf(authTagHash);
      hashBuf = authTagHashBuf.slice(0, authenticationTagBits[algorithms.hashAlgorithm]);
    } catch (err) {
      debug('Error Decrypt: ', err.message);
      throw errors.DECRYPTION_ERROR(': ' + err.message);
    }

    if (base64urlEscape(hashBuf.toString('base64')) !== origAuthenticationTag) {
      throw errors.DECRYPTION_ERROR('');
    } else {
      return {
        header: header,
        payload: JSON.parse(result)
      };
    }
  }

  function generateRandomInitializationVector() {
    var iv = [];
    for (var i = 0; i < 16; i++) {
      iv.push(Math.round(Math.random() * 255));
    }

    return new Buffer(iv);
  }

  function encryptJWT(payload, header, encKey, hashKey) {

    header = _.defaults(header, {
      alg: 'dir',
      enc: 'A256CBC-HS512'
    });

    if (!header.kid) {
      throw errors.MISSING_REQUIRED_KID();
    }

    var algorithms = getEncryptionAndHashAlgoritms(header.enc);

    var iv = generateRandomInitializationVector();

    var segments = [];

    var b64Header = encodeBase64url(new Buffer(JSON.stringify(header)).toString('base64'));
    segments.push(b64Header);

    var b64Jek = '';
    segments.push(b64Jek);

    var b64IV = encodeBase64url(iv.toString('base64'));
    segments.push(b64IV);

    var encKeyBuffer = new Buffer(encKey, 'hex');
    var cipher = crypto.createCipheriv(algorithms.cipherAlgorithm, encKeyBuffer, iv);

    var cipherTextBegin = cipher.update(new Buffer(JSON.stringify(payload), 'utf8'));

    var cipherTextEnd = cipher.final();

    var cipherTextBuf = Buffer.concat([convertSlowBufToBuf(cipherTextBegin), convertSlowBufToBuf(cipherTextEnd)]);

    var b64CipherText = encodeBase64url(cipherTextBuf.toString('base64'));
    segments.push(b64CipherText);

    // Calculate AuthTag

    var b64HeaderBuf = new Buffer(b64Header);

    // We have iv Buffer and cipherTextBuf Buffer calculated.

    var al = new Buffer(4);
    al.writeInt32BE(b64HeaderBuf.length * 8, 0);

    var buf4Clear = new Buffer(4);
    buf4Clear.fill(0);

    var alResult = Buffer.concat([buf4Clear, al]);

    var authTag = new Buffer(Buffer.concat([b64HeaderBuf, iv, cipherTextBuf, alResult]));

    var hashKeyBuffer = new Buffer(hashKey, 'hex');
    var base64str = crypto.createHmac(algorithms.hashAlgorithm, hashKeyBuffer).update(authTag).digest();

    var buf = convertSlowBufToBuf(base64str);

    var result = buf.slice(0, authenticationTagBits[algorithms.hashAlgorithm]);

    var b64AuthTag = encodeBase64url(result.toString('base64'));
    segments.push(b64AuthTag);

    return segments.join('.');
  }

  function makePayload(payload) {
    if (config.expiration !== 0) {
      payload.iat = payload.iat || parseInt(new Date().getTime() / 1000, 10);
      payload.exp = payload.exp || payload.iat + config.expiration;
    }
    return payload;
  }

  function checkPayload(token, cb) {
    var payload = token.payload;
    if (!payload) {
      return cb(errors.EMPTY_PAYLOAD());
    }

    var currentDate = parseInt(Date.now() / 1000, 10);

    if (payload.iat) {
      var iatParsed = parseInt(payload.iat, 10);
      if (isNaN(iatParsed) || payload.iat !== iatParsed) {
        return cb(errors.INVALID_IAT());
      }
      if (payload.iat > currentDate + config.futureTolerance) {
        return cb(errors.FUTURE_JWT());
      }
    } else {
      if (payload.hasOwnProperty('iat')) {
        return cb(errors.INVALID_IAT());
      } else if (config.expiration !== 0) {
        return cb(errors.MISSING_IAT(), token);
      }
    }

    if (config.expiration !== 0) {
      var expLimit = iatParsed + config.expiration;
      if (expLimit <= currentDate) {
        return cb(errors.NO_FRESH_JWT(), token);
      }
    }

    if (payload.exp) {
      var expParsed = parseInt(payload.exp, 10);

      if (isNaN(expParsed) || payload.exp !== expParsed) {
        return cb(errors.INVALID_EXP());
      }

      if (payload.exp <= currentDate) {
        return cb(errors.EXPIRED_JWT(), token);
      }
    } else {
      if (payload.hasOwnProperty('exp')) {
        return cb(errors.INVALID_EXP());
      }
    }

    return cb(null, token);
  }

  if (configuration) {
    if (configuration.expiration || configuration.expiration === 0) {
      config.expiration = configuration.expiration;
    } else {
      config.expiration = DEFAULT_CONFIG.expiration;
    }

    config.futureTolerance = configuration.futureTolerance || DEFAULT_CONFIG.futureTolerance;
  } else {
    config = DEFAULT_CONFIG;
  }
  return {
    buildJWTEncrypted: function(payload, header, encKey, hashKey, cb) {
      if (!header) {
        return cb(errors.MISSING_REQUIRED_HEADER());
      }
      var result;
      try {
        var completePayload = makePayload(payload);
        result = encryptJWT(completePayload, header, encKey, hashKey);
      } catch (err) {
        if (err.namespace && err.name) {
          return cb(err);
        } else {
          return cb(errors.ENCRYPTION_ERROR(err.message));
        }

      }
      cb(null, result);
    },

    buildJWT: function(payload, header, key, cb) {
      if (!header) {
        return cb(errors.MISSING_REQUIRED_HEADER());
      }
      if (!header.alg) {
        header.alg = 'HS256';
      }
      var result;
      try {
        var completePayload = makePayload(payload);
        result = encodeJWT(completePayload, header, key);
      } catch (err) {
        return cb(err);
      }
      cb(null, result);
    },

    readJWTEncrypted: function(jwtToken, encKey, hashKey, cb) {
      var result;
      try {
        result = decryptJWT(jwtToken, encKey, hashKey);
      } catch (err) {
        return cb(err);
      }
      debug('Decrypted data is %j', result);
      checkPayload(result, cb);
    },

    readJWT: function(jwtToken, key, cb) {
      var result;
      try {
        result = decodeJWT(jwtToken, key);
      } catch (err) {
        return cb(err);
      }
      debug('Unencoded data is %j', result);
      checkPayload(result, cb);
    },

    readJWTHeader: function(jwtToken, cb) {
      var result;
      try {
        var segments = jwtToken.split('.');
        result = readJWTHeader(segments[0]);
      } catch (err) {
        return cb(errors.INVALID_HEADER(err.message));
      }
      debug('Header is %j', result);
      cb(null, result);
    }
  };
};
