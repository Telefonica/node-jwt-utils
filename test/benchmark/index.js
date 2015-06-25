'use strict';

var jwt = require('../../index')();

/*jshint -W069 */
/*jshint -W106 */
/*jshint -W072*/
/*jshint -W098*/
/*jshint -W117*/

var HEADER = {
  kid: 'benchmark',
  corr: 'benchmark-correlator'
};

var PAYLOAD = {
  nonce: '1',
  client_id: 'benchmark',
  redirect_uri: 'http://localhost',
  iss: 'http://localhost:6543/benchmark',
  aud: 'http://localhost:6543',
  acr_values: '2 3'
};

var SECRET = '796f75722d7365637265742d6b657923796f75722d7365637265742d6b657923';

var TOTAL_TIMES = 2000;

var timesEncrypted = 0;

var start;

function benchmarkEncryptedTokens() {
  jwt.buildJWTEncrypted(PAYLOAD, HEADER, SECRET, SECRET, function(err, token) {
    timesEncrypted = timesEncrypted + 1;
    if (timesEncrypted === TOTAL_TIMES) {
      var elapsed = Date.now() - start;
      console.log('%d encrypted tokens generated in %d millis', TOTAL_TIMES, elapsed);
    } else {
      benchmarkEncryptedTokens();
    }
  });
}

var timesUnencrypted = 0;

function benchmarkUnencryptedTokens() {
  jwt.buildJWT(PAYLOAD, HEADER, SECRET, function(err, token) {
    timesUnencrypted = timesUnencrypted + 1;
    if (timesUnencrypted === TOTAL_TIMES) {
      var elapsed = Date.now() - start;
      console.log('%d unencrypted tokens generated in %d millis', TOTAL_TIMES, elapsed);
    } else {
      benchmarkUnencryptedTokens();
    }
  });
}

start = Date.now();
benchmarkEncryptedTokens();

start = Date.now();
benchmarkUnencryptedTokens();
