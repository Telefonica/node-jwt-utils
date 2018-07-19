jwt-utils
=========

JSON Web Tokens (JWT) utils.

[![npm version](https://badge.fury.io/js/jwt-utils.svg)](http://badge.fury.io/js/jwt-utils)
[![Build Status](https://travis-ci.org/telefonica/node-jwt-utils.svg)](https://travis-ci.org/telefonica/node-jwt-utils)
[![Coverage Status](https://img.shields.io/coveralls/telefonica/node-jwt-utils.svg)](https://coveralls.io/r/telefonica/node-jwt-utils)

This module is able to parse and generate both encrypted and unencrypted JWT tokens.

- A **hash key** (```hashKey```) is needed to generate a JWT signature.
- An **encryption key** (```encryptKey```) is needed only if you need to deal with encrypted JWT tokens.

This module only allows hexadecimal strings as hash and encryption keys. The encryption key must be
a 32-length hexadecimal value (16 bytes) if the encryption algorithm is ```A128CBC```.

The ```kid``` (key identifier) goes in the JWT header, and serves as a client identifier, in case you need
to use different keys for different clients.

## Installation

```bash
npm install jwt-utils
```

## Examples

```javascript
var config = { expiration: 600};
var jwt = require('jwt-utils')(config);

// Encode JWT token
jwt.buildJWT(payload, header, hashKey, function(err, token) {
    if (!err) {
        console.log(token); // something in the format "aaa.bbb.ccc"
    }
});

// Decode JWT token
jwt.readJWT(token, hashKey, function(err, token) {
    if (!err) {
        console.log(token.payload);
        console.log(token.header);
    }
});

// Encrypt JWT token
jwt.buildJWTEncrypted(payload, header, encryptKey, hashKey, function(err, token) {
    if (!err) {
        console.log(token); // something in the format "aaa.bbb.ccc.ddd.eee"
    }
});

// Decrypt JWT token
jwt.readJWTEncrypted(token, encryptKey, hashKey, function(err, token) {
    if (!err) {
        console.log(token.payload);
        console.log(token.header);
    }
});

// Read JWT header
jwt.readJWTHeader(token, function(err, header) {
    if (!err) {
        console.log(header);
    }
});
```

## Configuration

* expiration: Expiration time in seconds to generate exp field in token (this functionality can be disabled by setting the value to 0).
* futureTolerance: Tolerance seconds to find out if a jwt comes from the future or not.

## Development information

```
npm test
```

## Errors:
The following file has registered the error of this library:
[errors.json](errors.json)

## License

Copyright 2015 [Telefónica Investigación y Desarrollo, S.A.U](http://www.tid.es)

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
