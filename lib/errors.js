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

var therror = require('therror');

/**
 * JWT Utils errors.
 */
module.exports = therror.register({

  /**
   * The JWT header does not have the kid field.
   */
  MISSING_REQUIRED_KID: {
    message: 'Missing required kid.',
    level: 'info',
    namespace: 'JWTHEADER'
  },

  /**
   * The JWT header has an algorithm not supported.
   */
  ALGORITHM_NOT_SUPPORTED: {
    message: 'Algorithm not supported.',
    level: 'info',
    namespace: 'JWTHEADER'
  },

  /**
   * The JWT cannot be decoded.
   */
  INVALID_HEADER: {
    message: 'Invalid header.',
    level: 'info',
    namespace: 'JWTHEADER'
  },

  /**
   * The header argument is null or undefined.
   */
  MISSING_REQUIRED_HEADER: {
    message: 'Missing required header.',
    level: 'info',
    namespace: 'JWTHEADER'
  },

  /**
   * The key value is missing, and it is required.
   */
  MISSING_REQUIRED_KEY: {
    message: 'Missing required key.',
    level: 'info',
    namespace: 'JWT'
  },

  /**
   * The number of segments of the jwt are invalid.
   */
  SEGMENTS_NUMBER_ERROR: {
    message: 'Not enough or too many segments {1}.',
    level: 'info',
    namespace: 'JWT'
  },

  /**
   * The hash key or the hash are invalid.
   */
  WRONG_TOKEN_SIGNATURE: {
    message: 'Wrong token signature',
    level: 'info',
    namespace: 'JWT'
  },

  /**
   * The value of the fourth segment of an encrypted jwt is invalid.
   */
  INVALID_FOURTH_SEGMENT: {
    message: 'The fourth segment must not be null.',
    level: 'info',
    namespace: 'JWT'
  },

  /**
   * Error decrypting an jwt encrypted.
   */
  DECRYPTION_ERROR: {
    message: 'JWT cannot be decrypted{1}',
    level: 'info',
    namespace: 'JWT'
  },

  /**
   * Error when it tries to encrypt in order to generate a jwt encrypted.
   */
  ENCRYPTION_ERROR: {
    message: 'Encryption error: {1}',
    level: 'info',
    namespace: 'JWT'
  },

  /**
   * Invalid iat value.
   */
  INVALID_IAT: {
    message: 'JWT iat is not valid.',
    level: 'info',
    namespace: 'JWTPAYLOAD'
  },

  /**
   * Iat is required.
   */
  MISSING_IAT: {
    message: 'iat field is missing in the JWT payload.',
    level: 'info',
    namespace: 'JWTPAYLOAD'
  },

  /**
   * Invalid exp value.
   */
  INVALID_EXP: {
    message: 'JWT exp is not valid.',
    level: 'info',
    namespace: 'JWTPAYLOAD'
  },

  /**
   * The payload of the token is empty.
   */
  EMPTY_PAYLOAD: {
    message: 'Empty payload',
    level: 'info',
    namespace: 'JWTPAYLOAD'
  },

  /**
   * The jwt has expired taking into account the configured value.
   */
  EXPIRED_JWT: {
    message: 'JWT has expired.',
    level: 'info',
    namespace: 'JWTPAYLOAD'
  },

  /**
   * The jwt has discarded by client. Current time is greater than client expiration.
   */
  NO_FRESH_JWT: {
    message: 'JWT has discarded by client. No fresh JWT.',
    level: 'info',
    namespace: 'JWTPAYLOAD'
  },

  /**
   * The jwt has an invalid date. Perhaps the machine clocks has some differences or you may suffering an attack.
   */
  FUTURE_JWT: {
    message: 'JWT belongs to the future.',
    level: 'info',
    namespace: 'JWTPAYLOAD'
  }
});
