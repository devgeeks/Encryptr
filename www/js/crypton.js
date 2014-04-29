/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
*/

var crypton = {};

(function () {

'use strict';

/**!
 * ### version
 * Holds framework version for potential future backward compatibility
 */
crypton.version = '0.0.2';

/**!
 * ### host
 * Holds location of Crypton server
 */
crypton.host = location.hostname;

/**!
 * ### port
 * Holds port of Crypton server
 */
crypton.port = 443;

/**!
 * ### cipherOptions
 * Sets AES mode to GCM, necessary for SJCL
 */
crypton.cipherOptions = {
  mode: 'gcm'
};

/**!
 * ### paranoia
 * Tells SJCL how strict to be about PRNG readiness
 */
crypton.paranoia = 6;

/**!
 * ### trustStateContainer
 * Internal name for trust state container
 */
crypton.trustStateContainer = '_trust_state';

/**!
 * ### collectorsStarted
 * Internal flag to know if startCollectors has been called
 */
crypton.collectorsStarted = false;

/**!
 * ### startCollectors
 * Start sjcl.random listeners for adding to entropy pool
 */
crypton.startCollectors = function () {
  sjcl.random.startCollectors();
  crypton.collectorsStarted = true;
};

/**!
 * ### url()
 * Generate URLs for server calls
 *
 * @return {String} url
 */
crypton.url = function () {
  return 'https://' + crypton.host + ':' + crypton.port;
};

/**!
 * ### randomBytes(nbytes)
 * Generate `nbytes` bytes of random data
 *
 * @param {Number} nbytes
 * @return {Array} bitArray
 */
function randomBytes (nbytes) {
  if (!nbytes) {
    throw new Error('randomBytes requires input');
  }

  if (parseInt(nbytes, 10) !== nbytes) {
    throw new Error('randomBytes requires integer input');
  }

  if (nbytes < 4) {
    throw new Error('randomBytes cannot return less than 4 bytes');
  }

  if (nbytes % 4 !== 0) {
    throw new Error('randomBytes requires input as multiple of 4');
  }

  // sjcl's words are 4 bytes (32 bits)
  var nwords = nbytes / 4;
  return sjcl.random.randomWords(nwords);
}
crypton.randomBytes = randomBytes;

/**!
 * ### constEqual()
 * Compare two strings in constant time.
 *
 * @param {String} str1
 * @param {String} str2
 * @return {bool} equal
 */
function constEqual (str1, str2) {
  // We only support string comparison, we could support Arrays but
  // they would need to be single char elements or compare multichar
  // elements constantly. Going for simplicity for now.
  // TODO: Consider this ^
  if (typeof str1 !== 'string' || typeof str2 !== 'string') {
    return false;
  }

  var mismatch = str1.length ^ str2.length;
  var len = Math.min(str1.length, str2.length);

  for (var i = 0; i < len; i++) {
    mismatch |= str1.charCodeAt(i) ^ str2.charCodeAt(i);
  }

  return mismatch === 0;
}
crypton.constEqual = constEqual;

/**!
 * ### randomBits(nbits)
 * Generate `nbits` bits of random data
 *
 * @param {Number} nbits
 * @return {Array} bitArray
 */
crypton.randomBits = function (nbits) {
  if (!nbits) {
    throw new Error('randomBits requires input');
  }

  if (parseInt(nbits, 10) !== nbits) {
    throw new Error('randomBits requires integer input');
  }

  if (nbits < 32) {
    throw new Error('randomBits cannot return less than 32 bits');
  }

  if (nbits % 32 !== 0) {
    throw new Error('randomBits requires input as multiple of 32');
  }

  var nbytes = nbits / 8;
  return crypton.randomBytes(nbytes);
};

/**!
 * ### mac(key, data)
 * Generate an HMAC using `key` for `data`.
 *
 * @param {String} key
 * @param {String} data
 * @return {String} hmacHex
 */
crypton.hmac = function(key, data) {
  var mac = new sjcl.misc.hmac(key);
  return sjcl.codec.hex.fromBits(mac.mac(data));
}

/**!
 * ### macAndCompare(key, data, otherMac)
 * Generate an HMAC using `key` for `data` and compare it in
 * constant time to `otherMac`.
 *
 * @param {String} key
 * @param {String} data
 * @param {String} otherMac
 * @return {Bool} compare succeeded
 */
crypton.hmacAndCompare = function(key, data, otherMac) {
  var ourMac = crypton.hmac(key, data);
  return crypton.constEqual(ourMac, otherMac);
}

/**!
 * ### fingerprint(pubKey, signKeyPub)
 * Generate a fingerprint for an account or peer.
 *
 * @param {PublicKey} pubKey
 * @param {PublicKey} signKeyPub
 * @return {String} hash
 */
// TODO check inputs
crypton.fingerprint = function (pubKey, signKeyPub) {
  var pubKeys = sjcl.bitArray.concat(
    pubKey._point.toBits(),
    signKeyPub._point.toBits()
  );

  var pubKeyHash = sjcl.hash.sha256.hash(pubKeys);
  return sjcl.codec.hex.fromBits(pubKeyHash);
};

/**!
 * ### generateAccount(username, passphrase, callback, options)
 * Generate salts and keys necessary for an account
 *
 * Saves account to server unless `options.save` is falsey
 *
 * Calls back with account and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} username
 * @param {String} passphrase
 * @param {Function} callback
 * @param {Object} options
 */
// TODO consider moving non-callback arguments to single object
crypton.generateAccount = function (username, passphrase, callback, options) {
  options = options || {};

  if (!username || !passphrase) {
    return callback('Must supply username and passphrase');
  }

  if (!crypton.collectorsStarted) {
    crypton.startCollectors();
  }

  var SIGN_KEY_BIT_LENGTH = 384;
  var keypairCurve = options.keypairCurve || 384;
  var save = typeof options.save !== 'undefined' ? options.save : true;

  var account = new crypton.Account();
  var hmacKey = randomBytes(32);
  var keypairSalt = randomBytes(32);
  var keypairMacSalt = randomBytes(32);
  var signKeyPrivateMacSalt = randomBytes(32);
  var containerNameHmacKey = randomBytes(32);
  var keypairKey = sjcl.misc.pbkdf2(passphrase, keypairSalt);
  var keypairMacKey = sjcl.misc.pbkdf2(passphrase, keypairMacSalt);
  var signKeyPrivateMacKey = sjcl.misc.pbkdf2(passphrase, signKeyPrivateMacSalt);
  var keypair = sjcl.ecc.elGamal.generateKeys(keypairCurve, crypton.paranoia);
  var signingKeys = sjcl.ecc.ecdsa.generateKeys(SIGN_KEY_BIT_LENGTH, crypton.paranoia);

  var srp = new SRPClient(username, passphrase, 2048, 'sha-256');
  var srpSalt = srp.randomHexSalt();
  var srpVerifier = srp.calculateV(srpSalt).toString(16);

  account.username = username;
  account.keypairSalt = JSON.stringify(keypairSalt);
  account.keypairMacSalt = JSON.stringify(keypairMacSalt);
  account.signKeyPrivateMacSalt = JSON.stringify(signKeyPrivateMacSalt);

  // Pad verifier to 512 bytes
  // TODO: This length will change when a different SRP group is used
  account.srpVerifier = srp.nZeros(512 - srpVerifier.length) + srpVerifier;
  account.srpSalt = srpSalt;

  // pubkeys
  account.pubKey = JSON.stringify(keypair.pub.serialize());
  account.signKeyPub = JSON.stringify(signingKeys.pub.serialize());

  var sessionIdentifier = 'dummySession';
  var session = new crypton.Session(sessionIdentifier);
  session.account = account;
  session.account.signKeyPrivate = signingKeys.sec;

  var selfPeer = new crypton.Peer({
    session: session,
    pubKey: keypair.pub
  });
  selfPeer.trusted = true;

  // hmac keys
  var encryptedHmacKey = selfPeer.encryptAndSign(JSON.stringify(hmacKey));
  if (encryptedHmacKey.error) {
    callback(encryptedHmacKey.error, null);
    return;
  }

  account.hmacKeyCiphertext = JSON.stringify(encryptedHmacKey);

  var encryptedContainerNameHmacKey = selfPeer.encryptAndSign(JSON.stringify(containerNameHmacKey));
  if (encryptedContainerNameHmacKey.error) {
    callback(encryptedContainerNameHmacKey.error, null);
    return;
  }

  account.containerNameHmacKeyCiphertext = JSON.stringify(encryptedContainerNameHmacKey);

  // private keys
  // TODO: Check data auth with hmac
  account.keypairCiphertext = sjcl.encrypt(keypairKey, JSON.stringify(keypair.sec.serialize()), crypton.cipherOptions);
  account.keypairMac = crypton.hmac(keypairMacKey, account.keypairCiphertext);
  account.signKeyPrivateCiphertext = sjcl.encrypt(keypairKey, JSON.stringify(signingKeys.sec.serialize()), crypton.cipherOptions);
  account.signKeyPrivateMac = crypton.hmac(signKeyPrivateMacKey, account.signKeyPrivateCiphertext);

  if (save) {
    account.save(function (err) {
      callback(err, account);
    });
    return;
  }

  callback(null, account);
};

/**!
 * ### authorize(username, passphrase, callback)
 * Perform zero-knowledge authorization with given `username`
 * and `passphrase`, generating a session if successful
 *
 * Calls back with session and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * SRP variables are named as defined in RFC 5054
 * and RFC 2945, prefixed with 'srp'
 *
 * @param {String} username
 * @param {String} passphrase
 * @param {Function} callback
 */
crypton.authorize = function (username, passphrase, callback) {
  if (!username || !passphrase) {
    return callback('Must supply username and passphrase');
  }

  if (!crypton.collectorsStarted) {
    crypton.startCollectors();
  }

  var options = {
    username: username,
    passphrase: passphrase
  };

  crypton.work.calculateSrpA(options, function (err, data) {
    if (err) {
      return callback(err);
    }

    var response = {
      srpA: data.srpAstr
    };

    superagent.post(crypton.url() + '/account/' + username)
      .withCredentials()
      .send(response)
      .end(function (res) {
        if (!res.body || res.body.success !== true) {
          return callback(res.body.error);
        }

        options.a = data.a;
        options.srpA = data.srpA;
        options.srpB = res.body.srpB;
        options.srpSalt = res.body.srpSalt;

        // calculateSrpM1
        crypton.work.calculateSrpM1(options, function (err, srpM1, ourSrpM2) {
          response = {
            srpM1: srpM1
          };

          superagent.post(crypton.url() + '/account/' + username + '/answer')
            .withCredentials()
            .send(response)
            .end(function (res) {
              if (!res.body || res.body.success !== true) {
                callback(res.body.error);
                return;
              }

              if (!constEqual(res.body.srpM2, ourSrpM2)) {
                callback('Server could not be verified');
                return;
              }

              var sessionIdentifier = res.body.sessionIdentifier;
              var session = new crypton.Session(sessionIdentifier);
              session.account = new crypton.Account();
              session.account.username = username;
              session.account.passphrase = passphrase;
              session.account.challengeKey = res.body.account.challengeKey;
              session.account.containerNameHmacKeyCiphertext = res.body.account.containerNameHmacKeyCiphertext;
              session.account.hmacKeyCiphertext = res.body.account.hmacKeyCiphertext;
              session.account.keypairCiphertext = res.body.account.keypairCiphertext;
              session.account.keypairMac = res.body.account.keypairMac;
              session.account.pubKey = res.body.account.pubKey;
              session.account.challengeKeySalt = res.body.account.challengeKeySalt;
              session.account.keypairSalt = res.body.account.keypairSalt;
              session.account.keypairMacSalt = res.body.account.keypairMacSalt;
              session.account.signKeyPub = res.body.account.signKeyPub;
              session.account.signKeyPrivateCiphertext = res.body.account.signKeyPrivateCiphertext;
              session.account.signKeyPrivateMacSalt = res.body.account.signKeyPrivateMacSalt;
              session.account.signKeyPrivateMac = res.body.account.signKeyPrivateMac;
              session.account.unravel(function (err) {
                if (err) {
                  return callback(err);
                }

                // check for internal peer trust state container
                session.load(crypton.trustStateContainer, function (err) {
                  // if it exists, callback with session
                  if (!err) {
                    return callback(null, session);
                  }

                  // if not, create it
                  session.create(crypton.trustStateContainer, function (err) {
                    if (err) {
                      return callback(err);
                    }

                    callback(null, session);
                  });
                });
              });
            });
        });
      });
  });
};

})();
/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
*/

(function() {

'use strict';

/**!
 * # Account()
 *
 * ````
 * var account = new crypton.Account();
 * ````
 */
var Account = crypton.Account = function Account () {};

/**!
 * ### save(callback)
 * Send the current account to the server to be saved
 *
 * Calls back without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {Function} callback
 */
Account.prototype.save = function (callback) {
  superagent.post(crypton.url() + '/account')
    .withCredentials()
    .send(this.serialize())
    .end(function (res) {
      if (res.body.success !== true) {
        callback(res.body.error);
      } else {
        callback();
      }
    }
  );
};

/**!
 * ### unravel(callback)
 * Decrypt raw account object from server after successful authentication
 *
 * Calls back without error if successful
 *
 * __Throws__ if unsuccessful
 *
 * @param {Function} callback
 */
Account.prototype.unravel = function (callback) {
  var that = this;

  crypton.work.unravelAccount(this, function (err, data) {
    if (err) {
      return callback(err);
    }

    that.regenerateKeys(data, function (err) {
      callback(err);
    });
  });
};

/**!
 * ### regenerateKeys(callback)
 * Reconstruct keys from unraveled data
 *
 * Calls back without error if successful
 *
 * __Throws__ if unsuccessful
 *
 * @param {Function} callback
 */
Account.prototype.regenerateKeys = function (data, callback) {
  // reconstruct secret key
  var exponent = sjcl.bn.fromBits(data.secret.exponent);
  this.secretKey = new sjcl.ecc.elGamal.secretKey(data.secret.curve, sjcl.ecc.curves['c' + data.secret.curve], exponent);

  // reconstruct public key
  var point = sjcl.ecc.curves['c' + this.pubKey.curve].fromBits(this.pubKey.point);
  this.pubKey = new sjcl.ecc.elGamal.publicKey(this.pubKey.curve, point.curve, point);

  // assign the hmac keys to the account
  this.hmacKey = data.hmacKey;
  this.containerNameHmacKey = data.containerNameHmacKey;

  // reconstruct the public signing key
  var signPoint = sjcl.ecc.curves['c' + this.signKeyPub.curve].fromBits(this.signKeyPub.point);
  this.signKeyPub = new sjcl.ecc.ecdsa.publicKey(this.signKeyPub.curve, signPoint.curve, signPoint);

  // reconstruct the secret signing key
  var signExponent = sjcl.bn.fromBits(data.signKeySecret.exponent);
  this.signKeyPrivate = new sjcl.ecc.ecdsa.secretKey(data.signKeySecret.curve, sjcl.ecc.curves['c' + data.signKeySecret.curve], signExponent);

  // calculate fingerprint for public key
  this.fingerprint = crypton.fingerprint(this.pubKey, this.signKeyPub);

  // recalculate the public points from secret exponents
  // and verify that they match what the server sent us
  var pubKeyHex = sjcl.codec.hex.fromBits(this.pubKey._point.toBits());
  var pubKeyShouldBe = this.secretKey._curve.G.mult(exponent);
  var pubKeyShouldBeHex = sjcl.codec.hex.fromBits(pubKeyShouldBe.toBits());

  if (!crypton.constEqual(pubKeyHex, pubKeyShouldBeHex)) {
    return callback('Server provided incorrect public key');
  }

  var signKeyPubHex = sjcl.codec.hex.fromBits(this.signKeyPub._point.toBits());
  var signKeyPubShouldBe = this.signKeyPrivate._curve.G.mult(signExponent);
  var signKeyPubShouldBeHex = sjcl.codec.hex.fromBits(signKeyPubShouldBe.toBits());

  if (!crypton.constEqual(signKeyPubHex, signKeyPubShouldBeHex)) {
    return callback('Server provided incorrect public signing key');
  }

  // sometimes the account object is used as a peer
  // to make the code simpler. verifyAndDecrypt checks
  // that the peer it is passed is trusted, or returns
  // an error. if we've gotten this far, we can be sure
  // that the public keys are trustable.
  this.trusted = true;

  callback(null);
};

/**!
 * ### serialize()
 * Package and return a JSON representation of the current account
 *
 * @return {Object}
 */
// TODO rename to toJSON
Account.prototype.serialize = function () {
  return {
    srpVerifier: this.srpVerifier,
    srpSalt: this.srpSalt,
    containerNameHmacKeyCiphertext: this.containerNameHmacKeyCiphertext,
    hmacKeyCiphertext: this.hmacKeyCiphertext,
    keypairCiphertext: this.keypairCiphertext,
    keypairMac: this.keypairMac,
    pubKey: this.pubKey,
    keypairSalt: this.keypairSalt,
    keypairMacSalt: this.keypairMacSalt,
    signKeyPrivateMacSalt: this.signKeyPrivateMacSalt,
    username: this.username,
    signKeyPub: this.signKeyPub,
    signKeyPrivateCiphertext: this.signKeyPrivateCiphertext,
    signKeyPrivateMac: this.signKeyPrivateMac
  };
};

/**!
 * ### verifyAndDecrypt()
 * Convienence function to verify and decrypt public key encrypted & signed data
 *
 * @return {Object}
 */
Account.prototype.verifyAndDecrypt = function (signedCiphertext, peer) {
  if (!peer.trusted) {
    return {
      error: 'Peer is untrusted'
    }
  }

  // hash the ciphertext
  var ciphertextString = JSON.stringify(signedCiphertext.ciphertext);
  var hash = sjcl.hash.sha256.hash(ciphertextString);
  // verify the signature
  var verified = false;
  try {
    verified = peer.signKeyPub.verify(hash, signedCiphertext.signature);
  } catch (ex) { }
  // try to decrypt regardless of verification failure
  try {
    var message = sjcl.decrypt(this.secretKey, ciphertextString, crypton.cipherOptions);
    if (verified) {
      return { plaintext: message, verified: verified, error: null };
    } else {
      return { plaintext: null, verified: false, error: 'Cannot verify ciphertext' };
    }
  } catch (ex) {
    return { plaintext: null, verified: false, error: 'Cannot verify ciphertext' };
  }
};
})();
/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
*/

(function () {

'use strict';

/**!
 * # Session(id)
 *
 * ````
 * var session = new crypton.Session(id);
 * ````
 *
 * @param {Number} id
 */
var Session = crypton.Session = function (id) {
  this.id = id;
  this.peers = [];
  this.events = [];
  this.containers = [];
  this.inbox = new crypton.Inbox(this);

  var that = this;
  this.socket = io.connect(crypton.url(), {
    secure: true
  });

  // watch for incoming Inbox messages
  this.socket.on('message', function (data) {
    that.inbox.get(data.messageId, function (err, message) {
      that.emit('message', message);
    });
  });

  // watch for container update notifications
  this.socket.on('containerUpdate', function (containerNameHmac) {
    // if any of the cached containers match the HMAC
    // in the notification, sync the container and
    // call the listener if one has been set
    for (var i in that.containers) {
      var container = that.containers[i];
      var temporaryHmac = container.containerNameHmac || container.getPublicName();

      if (crypton.constEqual(temporaryHmac, containerNameHmac)) {
        container.sync(function (err) {
          if (container._listener) {
            container._listener();
          }
        });

        break;
      }
    }
  });
};

/**!
 * ### load(containerName, callback)
 * Retieve container with given platintext `containerName`,
 * either from local cache or server
 *
 * Calls back with container and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} containerName
 * @param {Function} callback
 */
Session.prototype.load = function (containerName, callback) {
  // check for a locally stored container
  for (var i in this.containers) {
    if (crypton.constEqual(this.containers[i].name, containerName)) {
      callback(null, this.containers[i]);
      return;
    }
  }

  // check for a container on the server
  var that = this;
  this.getContainer(containerName, function (err, container) {
    if (err) {
      callback(err);
      return;
    }

    that.containers.push(container);
    callback(null, container);
  });
};

/**!
 * ### loadWithHmac(containerNameHmac, callback)
 * Retieve container with given `containerNameHmac`,
 * either from local cache or server
 *
 * Calls back with container and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} containerNameHmac
 * @param {Function} callback
 */
Session.prototype.loadWithHmac = function (containerNameHmac, peer, callback) {
  // check for a locally stored container
  for (var i in this.containers) {
    if (crypton.constEqual(this.containers[i].nameHmac, containerNameHmac)) {
      callback(null, this.containers[i]);
      return;
    }
  }

  // check for a container on the server
  var that = this;
  this.getContainerWithHmac(containerNameHmac, peer, function (err, container) {
    if (err) {
      callback(err);
      return;
    }

    that.containers.push(container);
    callback(null, container);
  });
};

/**!
 * ### create(containerName, callback)
 * Create container with given platintext `containerName`,
 * save it to server
 *
 * Calls back with container and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} containerName
 * @param {Function} callback
 */
Session.prototype.create = function (containerName, callback) {
  for (var i in this.containers) {
    if (crypton.constEqual(this.containers[i].name, containerName)) {
      callback('Container already exists');
      return;
    }
  }

  var selfPeer = new crypton.Peer({
    session: this,
    pubKey: this.account.pubKey,
    signKeyPub: this.account.signKeyPub
  });
  selfPeer.trusted = true;

  var sessionKey = crypton.randomBytes(32);
  var sessionKeyCiphertext = selfPeer.encryptAndSign(sessionKey);

  if (sessionKeyCiphertext.error) {
    return callback(sessionKeyCiphertext.error);
  }

  delete sessionKeyCiphertext.error;

  // TODO is signing the sessionKey even necessary if we're
  // signing the sessionKeyShare? what could the container
  // creator attack by wrapping a different sessionKey?
  var signature = 'hello';
  var containerNameHmac = new sjcl.misc.hmac(this.account.containerNameHmacKey);
  containerNameHmac = sjcl.codec.hex.fromBits(containerNameHmac.encrypt(containerName));

  // TODO why is a session object generating container payloads? creating the
  // initial container state should be done in container.js
  var rawPayloadCiphertext = sjcl.encrypt(sessionKey, JSON.stringify({
    recordIndex: 0,
    delta: {}
  }), crypton.cipherOptions);

  var payloadCiphertextHash = sjcl.hash.sha256.hash(JSON.stringify(rawPayloadCiphertext));
  var payloadSignature = this.account.signKeyPrivate.sign(payloadCiphertextHash, crypton.paranoia);

  var payloadCiphertext = {
    ciphertext: rawPayloadCiphertext,
    signature: payloadSignature
  };

  var that = this;
  new crypton.Transaction(this, function (err, tx) {
    var chunks = [
      {
        type: 'addContainer',
        containerNameHmac: containerNameHmac
      }, {
        type: 'addContainerSessionKey',
        containerNameHmac: containerNameHmac,
        signature: signature
      }, {
        type: 'addContainerSessionKeyShare',
        toAccount: that.account.username,
        containerNameHmac: containerNameHmac,
        sessionKeyCiphertext: sessionKeyCiphertext,
      }, {
        type: 'addContainerRecord',
        containerNameHmac: containerNameHmac,
        payloadCiphertext: payloadCiphertext
      }
    ];

    async.each(chunks, function (chunk, callback2) {
      tx.save(chunk, callback2);
    }, function (err) {
      if (err) {
        return tx.abort(function () {
          callback(err);
        });
      }

      tx.commit(function () {
        var container = new crypton.Container(that);
        container.name = containerName;
        container.sessionKey = sessionKey;
        that.containers.push(container);
        callback(null, container);
      });
    });
  });
};

/**!
 * ### deleteContainer(containerName, callback)
 * Request the server to delete all records and keys
 * belonging to `containerName`
 *
 * Calls back without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} containerName
 * @param {Function} callback
 */
Session.prototype.deleteContainer = function (containerName, callback) {
  var that = this;
  var containerNameHmac = new sjcl.misc.hmac(this.account.containerNameHmacKey);
  containerNameHmac = sjcl.codec.hex.fromBits(containerNameHmac.encrypt(containerName));

  new crypton.Transaction(this, function (err, tx) {
    var chunk = {
      type: 'deleteContainer',
      containerNameHmac: containerNameHmac
    };

    tx.save(chunk, function (err) {
      if (err) {
        return callback(err);
      }

      tx.commit(function (err) {
        callback(err);
      });
    });
  });
};


/**!
 * ### getContainer(containerName, callback)
 * Retrieve container with given platintext `containerName`
 * specifically from the server
 *
 * Calls back with container and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} containerName
 * @param {Function} callback
 */
Session.prototype.getContainer = function (containerName, callback) {
  var container = new crypton.Container(this);
  container.name = containerName;
  container.sync(function (err) {
    callback(err, container);
  });
};

/**!
 * ### getContainerWithHmac(containerNameHmac, callback)
 * Retrieve container with given `containerNameHmac`
 * specifically from the server
 *
 * Calls back with container and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} containerNameHmac
 * @param {Function} callback
 */
Session.prototype.getContainerWithHmac = function (containerNameHmac, peer, callback) {
  var container = new crypton.Container(this);
  container.nameHmac = containerNameHmac;
  container.peer = peer;
  container.sync(function (err) {
    callback(err, container);
  });
};

/**!
 * ### getPeer(containerName, callback)
 * Retrieve a peer object from the database for given `username`
 *
 * Calls back with peer and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {String} username
 * @param {Function} callback
 */
Session.prototype.getPeer = function (username, callback) {
  if (this.peers[username]) {
    return callback(null, this.peers[username]);
  }

  var that = this;
  var peer = new crypton.Peer();
  peer.username = username;
  peer.session = this;

  peer.fetch(function (err, peer) {
    if (err) {
      return callback(err);
    }

    that.load(crypton.trustStateContainer, function (err, container) {
      if (err) {
        return callback(err);
      }

      // if the peer has previously been trusted,
      // we should check the saved fingerprint against
      // what the server has given us
      if (!container.keys[username]) {
        peer.trusted = false;
      } else {
        var savedFingerprint = container.keys[username].fingerprint;

        if (!crypton.constEqual(savedFingerprint, peer.fingerprint)) {
          return callback('Server has provided malformed peer', peer);
        }

        peer.trusted = true;
      }

      that.peers[username] = peer;
      callback(null, peer);
    });
  });
};

/**!
 * ### on(eventName, listener)
 * Set `listener` to be called anytime `eventName` is emitted
 *
 * @param {String} eventName
 * @param {Function} listener
 */
// TODO allow multiple listeners
Session.prototype.on = function (eventName, listener) {
  this.events[eventName] = listener;
};

/**!
 * ### emit(eventName, data)
 * Call listener for `eventName`, passing it `data` as an argument
 *
 * @param {String} eventName
 * @param {Object} data
 */
// TODO allow multiple listeners
Session.prototype.emit = function (eventName, data) {
  this.events[eventName] && this.events[eventName](data);
};

})();

/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
*/

(function () {

'use strict';

/**!
 * # Container(session)
 *
 * ````
 * var container = new crypton.Container(session);
 * ````
 *
 * @param {Object} session
 */
var Container = crypton.Container = function (session) {
  this.keys = {};
  this.session = session;
  this.recordCount = 1;
  this.recordIndex = 0;
  this.versions = {};
  //this.version = +new Date();
  this.version = 0;
  this.name = null;
};

/**!
 * ### add(key, callback)
 * Add given `key` to the container
 *
 * Calls back without error if successful
 *
 * Calls back with error if unsuccessful
 * 
 * @param {String} key
 * @param {Function} callback
 */
Container.prototype.add = function (key, callback) {
  if (this.keys[key]) {
    callback('Key already exists');
    return;
  }

  this.keys[key] = {};
  callback();
};

/**!
 * ### get(key, callback)
 * Retrieve value for given `key`
 *
 * Calls back with `value` and without error if successful
 *
 * Calls back with error if unsuccessful
 * 
 * @param {String} key
 * @param {Function} callback
 */
Container.prototype.get = function (key, callback) {
  if (!this.keys[key]) {
    callback('Key does not exist');
    return;
  }

  callback(null, this.keys[key]);
};

/**!
 * ### save(callback, options)
 * Get difference of container since last save (a record),
 * encrypt the record, and send it to the server to be saved
 *
 * Calls back without error if successful
 *
 * Calls back with error if unsuccessful
 * 
 * @param {Function} callback
 * @param {Object} options (optional)
 */
Container.prototype.save = function (callback, options) {
  var that = this;

  this.getDiff(function (err, diff) {
    if (!diff) {
      callback('Container has not changed');
      return;
    }

    var payload = {
      recordIndex: that.recordCount,
      delta: diff
    };

    var now = +new Date();
    that.versions[now] = JSON.parse(JSON.stringify(that.keys));
    that.version = now;
    that.recordCount++;

    var rawPayloadCiphertext = sjcl.encrypt(that.sessionKey, JSON.stringify(payload), crypton.cipherOptions);
    var payloadCiphertextHash = sjcl.hash.sha256.hash(JSON.stringify(rawPayloadCiphertext));
    var payloadSignature = that.session.account.signKeyPrivate.sign(payloadCiphertextHash, crypton.paranoia);

    var payloadCiphertext = {
      ciphertext: rawPayloadCiphertext,
      signature: payloadSignature
    };

    var chunk = {
      type: 'addContainerRecord',
      containerNameHmac: that.getPublicName(),
      payloadCiphertext: payloadCiphertext
    };

    // if we aren't saving it, we're probably testing
    // to see if the transaction chunk was generated correctly
    if (options && options.save == false) {
      callback(null, chunk);
      return;
    }

    // TODO handle errs
    var tx = new crypton.Transaction(that.session, function (err) {
      tx.save(chunk, function (err) {
        tx.commit(function (err) {
          callback();
        });
      });
    });
  });
};

/**!
 * ### getDiff(callback, options)
 * Compute difference of container since last save
 *
 * Calls back with diff object and without error if successful
 *
 * Calls back with error if unsuccessful
 * 
 * @param {Function} callback
 */
Container.prototype.getDiff = function (callback) {
  var last = this.latestVersion();
  var old = this.versions[last] || {};
  callback(null, crypton.diff.create(old, this.keys));
};

/**!
 * ### getVersions()
 * Return a list of known save point timestamps
 *
 * @return {Array} timestamps
 */
Container.prototype.getVersions = function () {
  return Object.keys(this.versions);
};

/**!
 * ### getVersion(version)
 * Return full state of container at given `timestamp`
 *
 * @param {Number} timestamp
 * @return {Object} version
 */
Container.prototype.getVersion = function (timestamp) {
  return this.versions[timestamp];
};

/**!
 * ### getVersion()
 * Return last known save point timestamp
 *
 * @return {Number} version
 */
Container.prototype.latestVersion = function () {
  var versions = this.getVersions();

  if (!versions.length) {
    return this.version;
  } else {
    return Math.max.apply(Math, versions);
  }
};

/**!
 * ### getPublicName()
 * Compute the HMAC for the given name of the container
 *
 * @return {String} hmac
 */
Container.prototype.getPublicName = function () {
  if (this.nameHmac) {
    return this.nameHmac;
  }

  var hmac = new sjcl.misc.hmac(this.session.account.containerNameHmacKey);
  var containerNameHmac = hmac.encrypt(this.name);
  this.nameHmac = sjcl.codec.hex.fromBits(containerNameHmac);
  return this.nameHmac;
};

/**!
 * ### getHistory()
 * Ask the server for all state records
 *
 * Calls back with diff object and without error if successful
 *
 * Calls back with error if unsuccessful
 * 
 * @param {Function} callback
 */
Container.prototype.getHistory = function (callback) {
  var containerNameHmac = this.getPublicName();
  var currentVersion = this.latestVersion();

  var url = crypton.url() + '/container/' + containerNameHmac + '?after=' + (currentVersion + 1);
  superagent.get(url)
    .withCredentials()
    .end(function (res) {
      if (!res.body || res.body.success !== true) {
        callback(res.body.error);
        return;
      }

      callback(null, res.body.records);
    });
};

/**!
 * ### parseHistory(records, callback)
 * Loop through given `records`, decrypt them,
 * and build object state from decrypted diff objects
 *
 * Calls back with full container state,
 * history versions, last record index,
 * and without error if successful
 *
 * Calls back with error if unsuccessful
 * 
 * @param {Array} records
 * @param {Function} callback
 */
Container.prototype.parseHistory = function (records, callback) {
  var that = this;
  var keys = that.keys || {};
  var versions = that.versions || {};

  var recordIndex = that.recordIndex + 1;

  async.eachSeries(records, function (rawRecord, callback) {
    that.decryptRecord(recordIndex, rawRecord, function (err, record) {
      if (err) {
        return callback(err);
      }

      // TODO put in worker
      keys = crypton.diff.apply(record.delta, keys);

      // stringify and parse keys to ensure clean clone
      versions[record.time] = JSON.parse(JSON.stringify(keys));

      callback(null);
    });
  }, function (err) {
    if (err) {
      console.log('Hit error parsing container history');
      console.log(that);
      console.log(err);

      return callback(err);
    }

    that.recordIndex = recordIndex;
    callback(null, keys, versions, recordIndex);
  });
};

/**!
 * ### decryptRecord(recordIndex, record, callback)
 * Decrypt record ciphertext with session key,
 * verify record index
 *
 * Calls back with object containing timestamp and delta
 * and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {Object} recordIndex
 * @param {Object} record
 * @param {Object} callback
 */
Container.prototype.decryptRecord = function (recordIndex, record, callback) {
  if (!this.sessionKey) {
    this.decryptKey(record);
  }

  var parsedRecord;
  try {
    parsedRecord = JSON.parse(record.payloadCiphertext);
  } catch (e) {}

  if (!parsedRecord) {
    return callback('Could not parse record JSON');
  }

  var options = {
    sessionKey: this.sessionKey,
    expectedRecordIndex: recordIndex,
    record: record.payloadCiphertext,
    creationTime: record.creationTime,
    // we can't just send the peer object or its signKeyPub
    // here because of circular JSON when dealing with workers.
    // we'll have to reconstruct the signkey on the other end.
    // better to be explicit anyway!
    peerSignKeyPubSerialized: (
      this.peer && this.peer.signKeyPub || this.session.account.signKeyPub
    ).serialize()
  };

  crypton.work.decryptRecord(options, callback);
};

/**!
 * ### decryptKey(record)
 * Extract and decrypt the container's keys from a given record
 *
 * @param {Object} record
 */
Container.prototype.decryptKey = function (record) {
  var peer = this.peer || this.session.account;
  var sessionKeyRaw = this.session.account.verifyAndDecrypt(JSON.parse(record.sessionKeyCiphertext), peer);

  if (sessionKeyRaw.error) {
    throw new Error(sessionKeyRaw.error);
  }

  if (!sessionKeyRaw.verified) {
    throw new Error('Container session key signature mismatch');
  }

  this.sessionKey = JSON.parse(sessionKeyRaw.plaintext);
};

/**!
 * ### sync(callback)
 * Retrieve history, decrypt it, and update
 * container object with new state
 *
 * Calls back without error if successful
 *
 * Calls back with error if unsuccessful
 * 
 * @param {Function} callback
 */
Container.prototype.sync = function (callback) {
  var that = this;
  this.getHistory(function (err, records) {
    if (err) {
      callback(err);
      return;
    }

    that.parseHistory(records, function (err, keys, versions, recordIndexAfter) {
      that.keys = keys;
      that.versions = versions;
      that.version = Math.max.apply(Math, Object.keys(versions));
      that.recordCount = that.recordCount + versions.count;

      // TODO verify recordIndexAfter == recordCount?

      callback(err);
    });
  });
};

/**!
 * ### share(peer, callback)
 * Encrypt the container's sessionKey with peer's
 * public key, commit new addContainerSessionKey chunk,
 * and send a message to the peer informing them
 *
 * Calls back without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {Function} callback
 */
Container.prototype.share = function (peer, callback) {
  if (!this.sessionKey) {
    return callback('Container must be initialized to share');
  }

  // get the containerNameHmac
  // TODO this won't work if you aren't original sharer
  // because you won't have the original containerNameHmacKey.
  // we will have to mark containers as origin or remote
  var containerNameHmac = this.getPublicName();

  // encrypt sessionKey to peer's pubKey
  var sessionKeyCiphertext = peer.encryptAndSign(this.sessionKey);

  if (sessionKeyCiphertext.error) {
    return callback(sessionKeyCiphertext.error);
  }

  delete sessionKeyCiphertext.error;

  // create new addContainerSessionKeyShare chunk
  var that = this;
  new crypton.Transaction(this, function (err, tx) {
    var chunk = {
      type: 'addContainerSessionKeyShare',
      toAccount: peer.username,
      containerNameHmac: containerNameHmac,
      sessionKeyCiphertext: sessionKeyCiphertext
    };

    tx.save(chunk, function (err) {
      if (err) {
        return callback(err);
      }

      tx.commit(function (err) {
        if (err) {
          return callback(err);
        }

        // send a message informing peer
        // TODO we will have to add the ability to mark which application
        // this container belongs to, otherwise an application on the same
        // crypton server may incorrectly act upon this message
        peer.sendMessage({
          type: 'internal',
          action: 'containerShare'
        }, {
          fromUsername: that.session.account.username,
          containerNameHmac: containerNameHmac
        }, function (err) {
          callback(err);
        });
      });
    });
  });
};

/**!
 * ### watch(listener)
 * Attach a listener to the container
 * which is called if it is written to by a peer
 *
 * This is called after the container is synced
 *
 * @param {Function} callback
 */
Container.prototype.watch = function (listener) {
  this._listener = listener;
};

/**!
 * ### unwatch()
 * Remove an attached listener
 */
Container.prototype.unwatch = function () {
  delete this._listener;
};

})();

/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
*/

(function () {

'use strict';

/**!
 * # Transaction(session, callback)
 *
 * ````
 * var tx = new crypton.Transaction(session, function (err, tx) {
 *   // your code
 * });
 * ````
 *
 * @param {Object} session
 * @param {Function} callback
 */
var Transaction = crypton.Transaction = function (session, callback) {
  var that = this;
  this.session = session;
  this.types = [
    'addAccount',
    'setBaseKeyring',
    'addContainer',
    'deleteContainer',
    'addContainerSessionKey',
    'addContainerSessionKeyShare',
    'addContainerRecord',
    'addMessage',
    'deleteMessage'
  ];

  // necessary for testing
  if (!this.session) {
    callback && callback(null, this);
    return;
  }

  this.create(function (err, id) {
    if (err) {
      console.log(err);
      callback(err);
      return;
    }

    that.id = id;

    callback && callback(null, that);
  });
};

/**!
 * ### create(callback)
 * Ask the server for a new transaction id
 *
 * Calls back with transaction id and without error if successful
 *
 * Calls back with error if unsuccessful
 * 
 * @param {Function} callback
 */
Transaction.prototype.create = function (callback) {
  var url = crypton.url() + '/transaction/create';
  superagent.post(url)
    .withCredentials()
    .end(function (res) {
    if (!res.body || res.body.success !== true) {
      callback(res.body.error);
      return;
    }

    callback(null, res.body.id);
  });
};

/**!
 * ### save(chunk, ..., callback)
 * Save set of chunks to the server
 *
 * Calls back without error if successful
 *
 * Calls back with error if unsuccessful
 * 
 * @param {Object} chunk
 * @param {Function} callback
 */
Transaction.prototype.save = function () {
  this.verify();
  var that = this;
  var args = Array.prototype.slice.call(arguments);
  var callback = args.pop();

  if (typeof callback != 'function') {
    args.push(callback);
    callback = function () {};
  }

  async.each(args, function (chunk, cb) {
    // TODO check the type of the object
    if (typeof chunk == 'function') {
      cb();
      return;
    }

    that.saveChunk(chunk, cb);
  }, function (err) {
    callback(err);
  });
};

/**!
 * ### saveChunk(chunk, callback)
 * Save single chunk to the server
 *
 * Calls back without error if successful
 *
 * Calls back with error if unsuccessful
 * 
 * @param {Object} chunk
 * @param {Function} callback
 */
Transaction.prototype.saveChunk = function (chunk, callback) {
  this.verify();
  this.verifyChunk(chunk);
  var url = crypton.url() + '/transaction/' + this.id;

  superagent.post(url)
    .withCredentials()
    .send(chunk)
    .end(function (res) {
      if (!res.body || res.body.success !== true) {
        callback(res.body.error);
        return;
      }

      callback();
    });
};

/**!
 * ### commit(callback)
 * Ask the server to queue the transaction for committal
 *
 * Calls back without error if successful
 *
 * Calls back with error if unsuccessful
 * 
 * @param {Function} callback
 */
Transaction.prototype.commit = function (callback) {
  this.verify();
  var url = crypton.url() + '/transaction/' + this.id + '/commit';
  superagent.post(url)
    .withCredentials()
    .end(function (res) {
      if (!res.body || res.body.success !== true) {
        callback(res.body.error);
        return;
      }

      callback();
    });
};

/**!
 * ### abort(callback)
 * Ask the server to mark the transaction as aborted
 *
 * Calls back without error if successful
 *
 * Calls back with error if unsuccessful
 * 
 * @param {Function} callback
 */
Transaction.prototype.abort = function (callback) {
  this.verify();
  var url = crypton.url() + '/transaction/' + this.id;
  superagent.del(url)
    .withCredentials()
    .end(function (res) {
    if (!res.body || res.body.success !== true) {
      callback(res.body.error);
      return;
    }

    callback();
  });
};

/**!
 * ### verify()
 * Ensure the transaction is valid to be worked with
 *
 * Throws if unsuccessful
 */
Transaction.prototype.verify = function () {
  if (!this.id) {
    throw new Error('Invalid transaction');
  }
};

/**!
 * ### verifyChunk(chunk)
 * Ensure the provided `chunk` is fit to be sent to server
 *
 * Throws if unsuccessful
 *
 * @param {Object} chunk
 */
Transaction.prototype.verifyChunk = function (chunk) {
  if (!chunk || !~this.types.indexOf(chunk.type)) {
    throw new Error('Invalid transaction chunk type');
  }
};

})();

/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
*/

(function () {

'use strict';

/**!
 * # Peer(options)
 *
 * ````
 * var options = {
 *   username: 'friend' // required
 * };
 *
 * var peer = new crypton.Peer(options);
 * ````
 *
 * @param {Object} options
 */
var Peer = crypton.Peer = function (options) {
  options = options || {};

  this.accountId = options.id;
  this.session = options.session;
  this.username = options.username;
  this.pubKey = options.pubKey;
  this.signKeyPub = options.signKeyPub;
};

/**!
 * ### fetch(callback)
 * Retrieve peer data from server, applying it to parent object
 *
 * Calls back with peer data and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {Function} callback
 */
Peer.prototype.fetch = function (callback) {
  if (!this.username) {
    callback('Must supply peer username');
    return;
  }

  if (!this.session) {
    callback('Must supply session to peer object');
    return;
  }

  var that = this;
  var url = crypton.url() + '/peer/' + this.username;
  superagent.get(url)
    .withCredentials()
    .end(function (res) {
    if (!res.body || res.body.success !== true) {
      callback(res.body.error);
      return;
    }

    var peer = res.body.peer;
    that.accountId = peer.accountId;
    that.username = peer.username;
    that.pubKey = peer.pubKey;
    that.signKeyPub = peer.signKeyPub;
    // this may be necessary
    var point = sjcl.ecc.curves['c' + peer.pubKey.curve].fromBits(peer.pubKey.point);
    that.pubKey = new sjcl.ecc.elGamal.publicKey(peer.pubKey.curve, point.curve, point);
    var signPoint =
      sjcl.ecc.curves['c' + peer.signKeyPub.curve].fromBits(peer.signKeyPub.point);
    that.signKeyPub = new sjcl.ecc.ecdsa.publicKey(peer.signKeyPub.curve, signPoint.curve, signPoint);

    // calculate fingerprint for public key
    that.fingerprint = crypton.fingerprint(that.pubKey, that.signKeyPub);

    callback(null, that);
  });
};

/**!
 * ### encrypt(payload)
 * Encrypt `message` with peer's public key
 *
 * @param {Object} payload
 * @return {Object} ciphertext
 */
Peer.prototype.encrypt = function (payload) {
  if (!this.trusted) {
    return {
      error: 'Peer is untrusted'
    }
  }

  // should this be async to callback with an error if there is no pubkey?
  var ciphertext = sjcl.encrypt(this.pubKey, JSON.stringify(payload), crypton.cipherOptions);
  return ciphertext;
};

/**!
 * ### encryptAndSign(payload)
 * Encrypt `message` with peer's public key, sign the message with own signing key
 *
 * @param {Object} payload
 * @return {Object}
 */
Peer.prototype.encryptAndSign = function (payload) {
  if (!this.trusted) {
    return {
      error: 'Peer is untrusted'
    }
  }

  try {
    var ciphertext = sjcl.encrypt(this.pubKey, JSON.stringify(payload), crypton.cipherOptions);
    // hash the ciphertext and sign the hash:
    var hash = sjcl.hash.sha256.hash(ciphertext);
    var signature = this.session.account.signKeyPrivate.sign(hash, crypton.paranoia);
    return { ciphertext: JSON.parse(ciphertext), signature: signature, error: null };
  } catch (ex) {
    var err = "Error: Could not complete encryptAndSign: " + ex;
    return { ciphertext: null, signature: null, error: err };
  }
};

/**!
 * ### sendMessage(headers, payload, callback)
 * Encrypt `headers` and `payload` and send them to peer in one logical `message`
 *
 * Calls back with message id and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {Object} headers
 * @param {Object} payload
 */
Peer.prototype.sendMessage = function (headers, payload, callback) {
  if (!this.session) {
    callback('Must supply session to peer object');
    return;
  }

  var message = new crypton.Message(this.session);
  message.headers = headers;
  message.payload = payload;
  message.fromAccount = this.session.accountId;
  message.toAccount = this.accountId;
  message.encrypt(this);
  message.send(callback);
};

/**!
 * ### trust(callback)
 * Add peer's fingerprint to internal trust state container
 *
 * Calls back without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {Function} callback
 */
Peer.prototype.trust = function (callback) {
  var that = this;

  that.session.load(crypton.trustStateContainer, function (err, container) {
    if (err) {
      return callback(err);
    }

    if (container.keys[that.username]) {
      return callback('Peer is already trusted');
    }

    container.keys[that.username] = {
      trustedAt: +new Date(),
      fingerprint: that.fingerprint
    };

    container.save(function (err) {
      if (err) {
        return callback(err);
      }

      that.trusted = true;
      callback(null);
    });
  });
};

})();
/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
*/

(function() {

'use strict';

var Message = crypton.Message = function Message (session, raw) {
  this.session = session;
  this.headers = {};
  this.payload = {};

  raw = raw || {};
  for (var i in raw) {
    this[i] = raw[i];
  }
};

Message.prototype.encrypt = function (peer, callback) {
  var headersCiphertext = peer.encryptAndSign(this.headers);
  var payloadCiphertext = peer.encryptAndSign(this.payload);

  if (headersCiphertext.error || payloadCiphertext.error) {
    callback('Error encrypting headers or payload in Message.encrypt()');
    return;
  }

  this.encrypted = {
    headersCiphertext: JSON.stringify(headersCiphertext),
    payloadCiphertext: JSON.stringify(payloadCiphertext),
    fromUsername: this.session.account.username,
    toAccountId: peer.accountId
  };

  callback && callback(null);
};

Message.prototype.decrypt = function (callback) {
  var that = this;
  var headersCiphertext = JSON.parse(this.headersCiphertext);
  var payloadCiphertext = JSON.parse(this.payloadCiphertext);

  this.session.getPeer(this.fromUsername, function (err, peer) {
    if (err) {
      callback(err);
      return;
    }

    var headers = that.session.account.verifyAndDecrypt(headersCiphertext, peer);
    var payload = that.session.account.verifyAndDecrypt(payloadCiphertext, peer);
    if (!headers.verified || !payload.verified) {
      callback('Cannot verify headers or payload ciphertext in Message.decrypt()');
      return;
    } else if (headers.error || payload.error) {
      callback('Cannot decrypt headers or payload in Message.decrypt');
      return;
    }

    that.headers = JSON.parse(headers.plaintext);
    that.payload = JSON.parse(payload.plaintext);
    that.created = new Date(that.creationTime);
    callback(null, that);
  });
};

Message.prototype.send = function (callback) {
  if (!this.encrypted) {
    return callback('You must encrypt the message to a peer before sending!');
  }

  var url = crypton.url() + '/peer';
  superagent.post(url)
    .send(this.encrypted)
    .withCredentials()
    .end(function (res) {
    if (!res.body || res.body.success !== true) {
      callback(res.body.error);
      return;
    }

    callback(null, res.body.messageId);
  });
};

})();
/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
*/

(function() {

'use strict';

var Inbox = crypton.Inbox = function Inbox (session) {
  this.session = session;
  this.rawMessages = [];
  this.messages = {};

  this.poll();
};

Inbox.prototype.poll = function (callback) {
  var that = this;
  var url = crypton.url() + '/inbox';
  callback = callback || function () {};

  superagent.get(url)
    .withCredentials()
    .end(function (res) {
    if (!res.body || res.body.success !== true) {
      callback(res.body.error);
      return;
    }

    // should we merge or overwrite here?
    that.rawMessages = res.body.messages;
    that.parseRawMessages();

    callback(null, res.body.messages);
  });
};

Inbox.prototype.list = function () {
  // TODO should we poll here?
  return this.messages;
};

Inbox.prototype.filter = function (criteria, callback) {
  criteria = criteria || {};

  async.filter(this.messages, function (message) {
    for (var i in criteria) {
      if (message[i] != criteria[i]) {
        return false;
      }
    }

    return true;
  }, function (messages) {
    callback(messages);
  });
};

Inbox.prototype.get = function (messageId, callback) {
  var cachedMessage = this.messages[messageId];
  if (cachedMessage) {
    callback(null, cachedMessage);
    return;
  }

  var that = this;
  var url = crypton.url() + '/inbox/' + messageId;
  callback = callback || function () {};

  superagent.get(url)
    .withCredentials()
    .end(function (res) {
    if (!res.body || res.body.success !== true) {
      callback(res.body.error);
      return;
    }

    var message = new crypton.Message(that.session, res.body.message);
    message.decrypt(function (err) {
      that.messages[message.id] = message;
      callback(null, message);
    });
  });
};

Inbox.prototype.delete = function (id, callback) {
  var chunk = {
    type: 'deleteMessage',
    messageId: id
  };

  // TODO handle errs
  var tx = new crypton.Transaction(this.session, function (err) {
    tx.save(chunk, function (err) {
      tx.commit(function (err) {
        callback();
      });
    });
  });
};

Inbox.prototype.clear = function (callback) {
  // start + commit tx
  var chunk = {
    type: 'clearInbox'
  };

  // TODO handle errs
  var tx = new crypton.Transaction(this.session, function (err) {
    tx.save(chunk, function (err) {
      tx.commit(function (err) {
        callback();
      });
    });
  });
};

Inbox.prototype.parseRawMessages = function () {
  var that = this;

  for (var i in this.rawMessages) {
    var rawMessage = this.rawMessages[i];

    if (this.messages[rawMessage.messageId]) {
      continue;
    }

    var message = new crypton.Message(this.session, rawMessage);
    message.decrypt(function (err) {
      that.messages[message.messageId] = message;
    });
  }
};

})();
/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
*/

(function () {

'use strict';

var Diff = crypton.diff = {};

/**!
 * ### create(old, current)
 * Generate an object representing the difference between two inputs
 *
 * @param {Object} old
 * @param {Object} current
 * @return {Object} delta
 */
Diff.create = function (old, current) {
  var delta = jsondiffpatch.diff(old, current);
  return delta;
};

/**!
 * ### apply(delta, old)
 * Apply `delta` to `old` object to build `current` object
 *
 * @param {Object} delta
 * @param {Object} old
 * @return {Object} current
 */
// TODO should we switch the order of these arguments?
Diff.apply = function (delta, old) {
  var current = JSON.parse(JSON.stringify(old));
  jsondiffpatch.patch(current, delta);
  return current;
};

})();

/* Crypton Client, Copyright 2013 SpiderOak, Inc.
 *
 * This file is part of Crypton Client.
 *
 * Crypton Client is free software: you can redistribute it and/or modify it
 * under the terms of the Affero GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Crypton Client is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the Affero GNU General Public
 * License for more details.
 *
 * You should have received a copy of the Affero GNU General Public License
 * along with Crypton Client.  If not, see <http://www.gnu.org/licenses/>.
*/

(function() {

'use strict';

/*
 * if the browser supports web workers,
 * we "isomerize" crypton.work to transparently
 * put its methods in a worker and replace them
 * with a bridge API to said worker
*/
!self.worker && window.addEventListener('load', function () {
  var scriptEls = document.getElementsByTagName('script');
  var path;

  for (var i in scriptEls) {
    if (scriptEls[i].src && ~scriptEls[i].src.indexOf('crypton')) {
      path = scriptEls[i].src;
    }
  }

  isomerize(crypton.work, path)
}, false);

var work = crypton.work = {};

/**!
 * ### calculateSrpA(options, callback)
 * First step of authorization
 *
 * Calls back with SRP A values and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {Object} options
 * @param {Function} callback
 */
work.calculateSrpA = function (options, callback) {
  // srpRandom uses sjcl.random
  // and crypton.work might be in a different
  // thread than where startCollectors was originally called
  if (!crypton.collectorsStarted) {
    crypton.startCollectors();
  }

  try {
    var srp = new SRPClient(options.username, options.passphrase, 2048, 'sha-256');
    var a = srp.srpRandom();
    var srpA = srp.calculateA(a);

    // Pad A out to 512 bytes
    // TODO: This length will change when a different SRP group is used
    var srpAstr = srpA.toString(16);
    srpAstr = srp.nZeros(512 - srpAstr.length) + srpAstr;

    callback(null, {
      a: a.toString(),
      srpA: srpA.toString(),
      srpAstr: srpAstr
    });
  } catch (e) {
    console.log(e);
    callback(e);
  }
};

/**!
 * ### calculateSrpM1(options, callback)
 * Second step of authorization
 *
 * Calls back with SRP M1 value and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {Object} options
 * @param {Function} callback
 */
work.calculateSrpM1 = function (options, callback) {
  try {
    var srp = new SRPClient(options.username, options.passphrase, 2048, 'sha-256');
    var srpSalt = options.srpSalt;
    var a = new BigInteger(options.a);
    var srpA = new BigInteger(options.srpA);
    var srpB = new BigInteger(options.srpB, 16);

    var srpu = srp.calculateU(srpA, srpB);
    var srpS = srp.calculateS(srpB, options.srpSalt, srpu, a);
    var rawSrpM1 = srp.calculateMozillaM1(srpA, srpB, srpS);
    var srpM1 = rawSrpM1.toString(16);
    // Pad srpM1 to the full SHA-256 length
    srpM1 = srp.nZeros(64 - srpM1.length) + srpM1;

    var srpK = srp.calculateK(srpS);
    var srpM2 = srp.calculateMozillaM2(srpA, rawSrpM1, srpK).toString(16);

    callback(null, srpM1, srpM2);
  } catch (e) {
    console.log(e);
    callback(e);
  }
};

/**!
 * ### unravelAccount(account, callback)
 * Decrypt account keys, and pass them back
 * in a serialized form for reconstruction
 *
 * Calls back with key object and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {Object} account
 * @param {Function} callback
 */
work.unravelAccount = function (account, callback) {
  var ret = {};

  // regenerate keypair key from password
  var keypairKey = sjcl.misc.pbkdf2(account.passphrase, account.keypairSalt);
  var keypairMacKey = sjcl.misc.pbkdf2(account.passphrase, account.keypairMacSalt);
  var signKeyPrivateMacKey = sjcl.misc.pbkdf2(account.passphrase, account.signKeyPrivateMacSalt);

  var macOk = false;

  // decrypt secret key
  try {
    var ciphertextString = JSON.stringify(account.keypairCiphertext);
    macOk = crypton.hmacAndCompare(keypairMacKey, ciphertextString, account.keypairMac);
    ret.secret = JSON.parse(sjcl.decrypt(keypairKey, ciphertextString, crypton.cipherOptions));
  } catch (e) {}

  if (!macOk || !ret.secret) {
    // TODO could be decryption or parse error - should we specify?
    return callback('Could not parse secret key');
  }

  macOk = false;

  // decrypt signing key
  try {
    var ciphertextString = JSON.stringify(account.signKeyPrivateCiphertext);
    macOk = crypton.hmacAndCompare(signKeyPrivateMacKey, ciphertextString, account.signKeyPrivateMac);
    ret.signKeySecret = JSON.parse(sjcl.decrypt(keypairKey, ciphertextString, crypton.cipherOptions));
  } catch (e) {}

  if (!macOk || !ret.signKeySecret) {
    return callback('Could not parse signKeySecret');
  }

  var exponent = sjcl.bn.fromBits(ret.secret.exponent);
  var secretKey = new sjcl.ecc.elGamal.secretKey(ret.secret.curve, sjcl.ecc.curves['c' + ret.secret.curve], exponent);

  account.secretKey = secretKey;

  var session = {};
  session.account = account;
  session.account.signKeyPrivate = ret.signKeySecret;

  var signPoint = sjcl.ecc.curves['c' + account.signKeyPub.curve].fromBits(account.signKeyPub.point);

  var selfPeer = new crypton.Peer({
    session: session,
    pubKey: account.pubKey,
    signKeyPub: new sjcl.ecc.ecdsa.publicKey(account.signKeyPub.curve, signPoint.curve, signPoint)
  });
  selfPeer.trusted = true;

  var selfAccount = new crypton.Account();
  selfAccount.secretKey = secretKey;

  // decrypt hmac keys
  var containerNameHmacKey;
  try {
    containerNameHmacKey = selfAccount.verifyAndDecrypt(account.containerNameHmacKeyCiphertext, selfPeer);
    ret.containerNameHmacKey = JSON.parse(containerNameHmacKey.plaintext);
  } catch (e) {}

  if (!containerNameHmacKey.verified) {
    // TODO could be decryption or parse error - should we specify?
    return callback('Could not parse containerNameHmacKey');
  }

  var hmacKey;
  try {
    hmacKey = selfAccount.verifyAndDecrypt(account.hmacKeyCiphertext, selfPeer);
    ret.hmacKey = JSON.parse(hmacKey.plaintext);
  } catch (e) {}

  if (!hmacKey.verified) {
    // TODO could be decryption or parse error - should we specify?
    return callback('Could not parse hmacKey');
  }

  callback(null, ret);
};

/**!
 * ### decryptRecord(options, callback)
 * Decrypt a single record after checking its signature
 *
 * Calls back with decrypted record and without error if successful
 *
 * Calls back with error if unsuccessful
 *
 * @param {Object} options
 * @param {Function} callback
 */
work.decryptRecord = function (options, callback) {
  var sessionKey = options.sessionKey;
  var creationTime = options.creationTime;
  var expectedRecordIndex = options.expectedRecordIndex;
  var peerSignKeyPubSerialized = options.peerSignKeyPubSerialized;

  if (
    !sessionKey ||
    !creationTime ||
    !expectedRecordIndex ||
    !peerSignKeyPubSerialized
  ) {
    return callback('Must supply all options to work.decryptRecord');
  }

  var record;
  try {
    record = JSON.parse(options.record);
  } catch (e) {}

  if (!record) {
    return callback('Could not parse record');
  }

  // reconstruct the peer's public signing key
  // the key itself typically has circular references which
  // we can't pass around with JSON to/from a worker
  var curve = 'c' + peerSignKeyPubSerialized.curve;
  var signPoint = sjcl.ecc.curves[curve].fromBits(peerSignKeyPubSerialized.point);
  var peerSignKeyPub = new sjcl.ecc.ecdsa.publicKey(peerSignKeyPubSerialized.curve, signPoint.curve, signPoint);

  var verified = false;
  var payloadCiphertextHash = sjcl.hash.sha256.hash(JSON.stringify(record.ciphertext));

  try {
    verified = peerSignKeyPub.verify(payloadCiphertextHash, record.signature);
  } catch (e) {
    console.log(e);
  }

  if (!verified) {
    return callback('Record signature does not match expected signature');
  }

  var payload;
  try {
    payload = JSON.parse(sjcl.decrypt(sessionKey, record.ciphertext, crypton.cipherOptions));
  } catch (e) {}

  if (!payload) {
    return callback('Could not parse record payload');
  }

  if (payload.recordIndex !== expectedRecordIndex) {
    // TODO revisit
    // XXX ecto 3/4/14 I ran into a problem with this quite a while
    // ago where recordIndexes would never match even if they obviously
    // should. It smelled like an off-by-one or state error.
    // Now that record decryption is abstracted outside container instances,
    // we will have to do it in a different way anyway
    // (there was formerly a this.recordIndex++ here)

    // return callback('Record index mismatch');
  }

  callback(null, {
    time: +new Date(creationTime),
    delta: payload.delta
  });
};

})();
/*global setImmediate: false, setTimeout: false, console: false */
(function () {

    var async = {};

    // global on the server, window in the browser
    var root, previous_async;

    root = this;
    if (root != null) {
      previous_async = root.async;
    }

    async.noConflict = function () {
        root.async = previous_async;
        return async;
    };

    function only_once(fn) {
        var called = false;
        return function() {
            if (called) throw new Error("Callback was already called.");
            called = true;
            fn.apply(root, arguments);
        }
    }

    //// cross-browser compatiblity functions ////

    var _each = function (arr, iterator) {
        if (arr.forEach) {
            return arr.forEach(iterator);
        }
        for (var i = 0; i < arr.length; i += 1) {
            iterator(arr[i], i, arr);
        }
    };

    var _map = function (arr, iterator) {
        if (arr.map) {
            return arr.map(iterator);
        }
        var results = [];
        _each(arr, function (x, i, a) {
            results.push(iterator(x, i, a));
        });
        return results;
    };

    var _reduce = function (arr, iterator, memo) {
        if (arr.reduce) {
            return arr.reduce(iterator, memo);
        }
        _each(arr, function (x, i, a) {
            memo = iterator(memo, x, i, a);
        });
        return memo;
    };

    var _keys = function (obj) {
        if (Object.keys) {
            return Object.keys(obj);
        }
        var keys = [];
        for (var k in obj) {
            if (obj.hasOwnProperty(k)) {
                keys.push(k);
            }
        }
        return keys;
    };

    //// exported async module functions ////

    //// nextTick implementation with browser-compatible fallback ////
    if (typeof process === 'undefined' || !(process.nextTick)) {
        if (typeof setImmediate === 'function') {
            async.nextTick = function (fn) {
                // not a direct alias for IE10 compatibility
                setImmediate(fn);
            };
            async.setImmediate = async.nextTick;
        }
        else {
            async.nextTick = function (fn) {
                setTimeout(fn, 0);
            };
            async.setImmediate = async.nextTick;
        }
    }
    else {
        async.nextTick = process.nextTick;
        if (typeof setImmediate !== 'undefined') {
            async.setImmediate = setImmediate;
        }
        else {
            async.setImmediate = async.nextTick;
        }
    }

    async.each = function (arr, iterator, callback) {
        callback = callback || function () {};
        if (!arr.length) {
            return callback();
        }
        var completed = 0;
        _each(arr, function (x) {
            iterator(x, only_once(function (err) {
                if (err) {
                    callback(err);
                    callback = function () {};
                }
                else {
                    completed += 1;
                    if (completed >= arr.length) {
                        callback(null);
                    }
                }
            }));
        });
    };
    async.forEach = async.each;

    async.eachSeries = function (arr, iterator, callback) {
        callback = callback || function () {};
        if (!arr.length) {
            return callback();
        }
        var completed = 0;
        var iterate = function () {
            iterator(arr[completed], function (err) {
                if (err) {
                    callback(err);
                    callback = function () {};
                }
                else {
                    completed += 1;
                    if (completed >= arr.length) {
                        callback(null);
                    }
                    else {
                        iterate();
                    }
                }
            });
        };
        iterate();
    };
    async.forEachSeries = async.eachSeries;

    async.eachLimit = function (arr, limit, iterator, callback) {
        var fn = _eachLimit(limit);
        fn.apply(null, [arr, iterator, callback]);
    };
    async.forEachLimit = async.eachLimit;

    var _eachLimit = function (limit) {

        return function (arr, iterator, callback) {
            callback = callback || function () {};
            if (!arr.length || limit <= 0) {
                return callback();
            }
            var completed = 0;
            var started = 0;
            var running = 0;

            (function replenish () {
                if (completed >= arr.length) {
                    return callback();
                }

                while (running < limit && started < arr.length) {
                    started += 1;
                    running += 1;
                    iterator(arr[started - 1], function (err) {
                        if (err) {
                            callback(err);
                            callback = function () {};
                        }
                        else {
                            completed += 1;
                            running -= 1;
                            if (completed >= arr.length) {
                                callback();
                            }
                            else {
                                replenish();
                            }
                        }
                    });
                }
            })();
        };
    };


    var doParallel = function (fn) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            return fn.apply(null, [async.each].concat(args));
        };
    };
    var doParallelLimit = function(limit, fn) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            return fn.apply(null, [_eachLimit(limit)].concat(args));
        };
    };
    var doSeries = function (fn) {
        return function () {
            var args = Array.prototype.slice.call(arguments);
            return fn.apply(null, [async.eachSeries].concat(args));
        };
    };


    var _asyncMap = function (eachfn, arr, iterator, callback) {
        var results = [];
        arr = _map(arr, function (x, i) {
            return {index: i, value: x};
        });
        eachfn(arr, function (x, callback) {
            iterator(x.value, function (err, v) {
                results[x.index] = v;
                callback(err);
            });
        }, function (err) {
            callback(err, results);
        });
    };
    async.map = doParallel(_asyncMap);
    async.mapSeries = doSeries(_asyncMap);
    async.mapLimit = function (arr, limit, iterator, callback) {
        return _mapLimit(limit)(arr, iterator, callback);
    };

    var _mapLimit = function(limit) {
        return doParallelLimit(limit, _asyncMap);
    };

    // reduce only has a series version, as doing reduce in parallel won't
    // work in many situations.
    async.reduce = function (arr, memo, iterator, callback) {
        async.eachSeries(arr, function (x, callback) {
            iterator(memo, x, function (err, v) {
                memo = v;
                callback(err);
            });
        }, function (err) {
            callback(err, memo);
        });
    };
    // inject alias
    async.inject = async.reduce;
    // foldl alias
    async.foldl = async.reduce;

    async.reduceRight = function (arr, memo, iterator, callback) {
        var reversed = _map(arr, function (x) {
            return x;
        }).reverse();
        async.reduce(reversed, memo, iterator, callback);
    };
    // foldr alias
    async.foldr = async.reduceRight;

    var _filter = function (eachfn, arr, iterator, callback) {
        var results = [];
        arr = _map(arr, function (x, i) {
            return {index: i, value: x};
        });
        eachfn(arr, function (x, callback) {
            iterator(x.value, function (v) {
                if (v) {
                    results.push(x);
                }
                callback();
            });
        }, function (err) {
            callback(_map(results.sort(function (a, b) {
                return a.index - b.index;
            }), function (x) {
                return x.value;
            }));
        });
    };
    async.filter = doParallel(_filter);
    async.filterSeries = doSeries(_filter);
    // select alias
    async.select = async.filter;
    async.selectSeries = async.filterSeries;

    var _reject = function (eachfn, arr, iterator, callback) {
        var results = [];
        arr = _map(arr, function (x, i) {
            return {index: i, value: x};
        });
        eachfn(arr, function (x, callback) {
            iterator(x.value, function (v) {
                if (!v) {
                    results.push(x);
                }
                callback();
            });
        }, function (err) {
            callback(_map(results.sort(function (a, b) {
                return a.index - b.index;
            }), function (x) {
                return x.value;
            }));
        });
    };
    async.reject = doParallel(_reject);
    async.rejectSeries = doSeries(_reject);

    var _detect = function (eachfn, arr, iterator, main_callback) {
        eachfn(arr, function (x, callback) {
            iterator(x, function (result) {
                if (result) {
                    main_callback(x);
                    main_callback = function () {};
                }
                else {
                    callback();
                }
            });
        }, function (err) {
            main_callback();
        });
    };
    async.detect = doParallel(_detect);
    async.detectSeries = doSeries(_detect);

    async.some = function (arr, iterator, main_callback) {
        async.each(arr, function (x, callback) {
            iterator(x, function (v) {
                if (v) {
                    main_callback(true);
                    main_callback = function () {};
                }
                callback();
            });
        }, function (err) {
            main_callback(false);
        });
    };
    // any alias
    async.any = async.some;

    async.every = function (arr, iterator, main_callback) {
        async.each(arr, function (x, callback) {
            iterator(x, function (v) {
                if (!v) {
                    main_callback(false);
                    main_callback = function () {};
                }
                callback();
            });
        }, function (err) {
            main_callback(true);
        });
    };
    // all alias
    async.all = async.every;

    async.sortBy = function (arr, iterator, callback) {
        async.map(arr, function (x, callback) {
            iterator(x, function (err, criteria) {
                if (err) {
                    callback(err);
                }
                else {
                    callback(null, {value: x, criteria: criteria});
                }
            });
        }, function (err, results) {
            if (err) {
                return callback(err);
            }
            else {
                var fn = function (left, right) {
                    var a = left.criteria, b = right.criteria;
                    return a < b ? -1 : a > b ? 1 : 0;
                };
                callback(null, _map(results.sort(fn), function (x) {
                    return x.value;
                }));
            }
        });
    };

    async.auto = function (tasks, callback) {
        callback = callback || function () {};
        var keys = _keys(tasks);
        if (!keys.length) {
            return callback(null);
        }

        var results = {};

        var listeners = [];
        var addListener = function (fn) {
            listeners.unshift(fn);
        };
        var removeListener = function (fn) {
            for (var i = 0; i < listeners.length; i += 1) {
                if (listeners[i] === fn) {
                    listeners.splice(i, 1);
                    return;
                }
            }
        };
        var taskComplete = function () {
            _each(listeners.slice(0), function (fn) {
                fn();
            });
        };

        addListener(function () {
            if (_keys(results).length === keys.length) {
                callback(null, results);
                callback = function () {};
            }
        });

        _each(keys, function (k) {
            var task = (tasks[k] instanceof Function) ? [tasks[k]]: tasks[k];
            var taskCallback = function (err) {
                var args = Array.prototype.slice.call(arguments, 1);
                if (args.length <= 1) {
                    args = args[0];
                }
                if (err) {
                    var safeResults = {};
                    _each(_keys(results), function(rkey) {
                        safeResults[rkey] = results[rkey];
                    });
                    safeResults[k] = args;
                    callback(err, safeResults);
                    // stop subsequent errors hitting callback multiple times
                    callback = function () {};
                }
                else {
                    results[k] = args;
                    async.setImmediate(taskComplete);
                }
            };
            var requires = task.slice(0, Math.abs(task.length - 1)) || [];
            var ready = function () {
                return _reduce(requires, function (a, x) {
                    return (a && results.hasOwnProperty(x));
                }, true) && !results.hasOwnProperty(k);
            };
            if (ready()) {
                task[task.length - 1](taskCallback, results);
            }
            else {
                var listener = function () {
                    if (ready()) {
                        removeListener(listener);
                        task[task.length - 1](taskCallback, results);
                    }
                };
                addListener(listener);
            }
        });
    };

    async.waterfall = function (tasks, callback) {
        callback = callback || function () {};
        if (tasks.constructor !== Array) {
          var err = new Error('First argument to waterfall must be an array of functions');
          return callback(err);
        }
        if (!tasks.length) {
            return callback();
        }
        var wrapIterator = function (iterator) {
            return function (err) {
                if (err) {
                    callback.apply(null, arguments);
                    callback = function () {};
                }
                else {
                    var args = Array.prototype.slice.call(arguments, 1);
                    var next = iterator.next();
                    if (next) {
                        args.push(wrapIterator(next));
                    }
                    else {
                        args.push(callback);
                    }
                    async.setImmediate(function () {
                        iterator.apply(null, args);
                    });
                }
            };
        };
        wrapIterator(async.iterator(tasks))();
    };

    var _parallel = function(eachfn, tasks, callback) {
        callback = callback || function () {};
        if (tasks.constructor === Array) {
            eachfn.map(tasks, function (fn, callback) {
                if (fn) {
                    fn(function (err) {
                        var args = Array.prototype.slice.call(arguments, 1);
                        if (args.length <= 1) {
                            args = args[0];
                        }
                        callback.call(null, err, args);
                    });
                }
            }, callback);
        }
        else {
            var results = {};
            eachfn.each(_keys(tasks), function (k, callback) {
                tasks[k](function (err) {
                    var args = Array.prototype.slice.call(arguments, 1);
                    if (args.length <= 1) {
                        args = args[0];
                    }
                    results[k] = args;
                    callback(err);
                });
            }, function (err) {
                callback(err, results);
            });
        }
    };

    async.parallel = function (tasks, callback) {
        _parallel({ map: async.map, each: async.each }, tasks, callback);
    };

    async.parallelLimit = function(tasks, limit, callback) {
        _parallel({ map: _mapLimit(limit), each: _eachLimit(limit) }, tasks, callback);
    };

    async.series = function (tasks, callback) {
        callback = callback || function () {};
        if (tasks.constructor === Array) {
            async.mapSeries(tasks, function (fn, callback) {
                if (fn) {
                    fn(function (err) {
                        var args = Array.prototype.slice.call(arguments, 1);
                        if (args.length <= 1) {
                            args = args[0];
                        }
                        callback.call(null, err, args);
                    });
                }
            }, callback);
        }
        else {
            var results = {};
            async.eachSeries(_keys(tasks), function (k, callback) {
                tasks[k](function (err) {
                    var args = Array.prototype.slice.call(arguments, 1);
                    if (args.length <= 1) {
                        args = args[0];
                    }
                    results[k] = args;
                    callback(err);
                });
            }, function (err) {
                callback(err, results);
            });
        }
    };

    async.iterator = function (tasks) {
        var makeCallback = function (index) {
            var fn = function () {
                if (tasks.length) {
                    tasks[index].apply(null, arguments);
                }
                return fn.next();
            };
            fn.next = function () {
                return (index < tasks.length - 1) ? makeCallback(index + 1): null;
            };
            return fn;
        };
        return makeCallback(0);
    };

    async.apply = function (fn) {
        var args = Array.prototype.slice.call(arguments, 1);
        return function () {
            return fn.apply(
                null, args.concat(Array.prototype.slice.call(arguments))
            );
        };
    };

    var _concat = function (eachfn, arr, fn, callback) {
        var r = [];
        eachfn(arr, function (x, cb) {
            fn(x, function (err, y) {
                r = r.concat(y || []);
                cb(err);
            });
        }, function (err) {
            callback(err, r);
        });
    };
    async.concat = doParallel(_concat);
    async.concatSeries = doSeries(_concat);

    async.whilst = function (test, iterator, callback) {
        if (test()) {
            iterator(function (err) {
                if (err) {
                    return callback(err);
                }
                async.whilst(test, iterator, callback);
            });
        }
        else {
            callback();
        }
    };

    async.doWhilst = function (iterator, test, callback) {
        iterator(function (err) {
            if (err) {
                return callback(err);
            }
            if (test()) {
                async.doWhilst(iterator, test, callback);
            }
            else {
                callback();
            }
        });
    };

    async.until = function (test, iterator, callback) {
        if (!test()) {
            iterator(function (err) {
                if (err) {
                    return callback(err);
                }
                async.until(test, iterator, callback);
            });
        }
        else {
            callback();
        }
    };

    async.doUntil = function (iterator, test, callback) {
        iterator(function (err) {
            if (err) {
                return callback(err);
            }
            if (!test()) {
                async.doUntil(iterator, test, callback);
            }
            else {
                callback();
            }
        });
    };

    async.queue = function (worker, concurrency) {
        if (concurrency === undefined) {
            concurrency = 1;
        }
        function _insert(q, data, pos, callback) {
          if(data.constructor !== Array) {
              data = [data];
          }
          _each(data, function(task) {
              var item = {
                  data: task,
                  callback: typeof callback === 'function' ? callback : null
              };

              if (pos) {
                q.tasks.unshift(item);
              } else {
                q.tasks.push(item);
              }

              if (q.saturated && q.tasks.length === concurrency) {
                  q.saturated();
              }
              async.setImmediate(q.process);
          });
        }

        var workers = 0;
        var q = {
            tasks: [],
            concurrency: concurrency,
            saturated: null,
            empty: null,
            drain: null,
            push: function (data, callback) {
              _insert(q, data, false, callback);
            },
            unshift: function (data, callback) {
              _insert(q, data, true, callback);
            },
            process: function () {
                if (workers < q.concurrency && q.tasks.length) {
                    var task = q.tasks.shift();
                    if (q.empty && q.tasks.length === 0) {
                        q.empty();
                    }
                    workers += 1;
                    var next = function () {
                        workers -= 1;
                        if (task.callback) {
                            task.callback.apply(task, arguments);
                        }
                        if (q.drain && q.tasks.length + workers === 0) {
                            q.drain();
                        }
                        q.process();
                    };
                    var cb = only_once(next);
                    worker(task.data, cb);
                }
            },
            length: function () {
                return q.tasks.length;
            },
            running: function () {
                return workers;
            }
        };
        return q;
    };

    async.cargo = function (worker, payload) {
        var working     = false,
            tasks       = [];

        var cargo = {
            tasks: tasks,
            payload: payload,
            saturated: null,
            empty: null,
            drain: null,
            push: function (data, callback) {
                if(data.constructor !== Array) {
                    data = [data];
                }
                _each(data, function(task) {
                    tasks.push({
                        data: task,
                        callback: typeof callback === 'function' ? callback : null
                    });
                    if (cargo.saturated && tasks.length === payload) {
                        cargo.saturated();
                    }
                });
                async.setImmediate(cargo.process);
            },
            process: function process() {
                if (working) return;
                if (tasks.length === 0) {
                    if(cargo.drain) cargo.drain();
                    return;
                }

                var ts = typeof payload === 'number'
                            ? tasks.splice(0, payload)
                            : tasks.splice(0);

                var ds = _map(ts, function (task) {
                    return task.data;
                });

                if(cargo.empty) cargo.empty();
                working = true;
                worker(ds, function () {
                    working = false;

                    var args = arguments;
                    _each(ts, function (data) {
                        if (data.callback) {
                            data.callback.apply(null, args);
                        }
                    });

                    process();
                });
            },
            length: function () {
                return tasks.length;
            },
            running: function () {
                return working;
            }
        };
        return cargo;
    };

    var _console_fn = function (name) {
        return function (fn) {
            var args = Array.prototype.slice.call(arguments, 1);
            fn.apply(null, args.concat([function (err) {
                var args = Array.prototype.slice.call(arguments, 1);
                if (typeof console !== 'undefined') {
                    if (err) {
                        if (console.error) {
                            console.error(err);
                        }
                    }
                    else if (console[name]) {
                        _each(args, function (x) {
                            console[name](x);
                        });
                    }
                }
            }]));
        };
    };
    async.log = _console_fn('log');
    async.dir = _console_fn('dir');
    /*async.info = _console_fn('info');
    async.warn = _console_fn('warn');
    async.error = _console_fn('error');*/

    async.memoize = function (fn, hasher) {
        var memo = {};
        var queues = {};
        hasher = hasher || function (x) {
            return x;
        };
        var memoized = function () {
            var args = Array.prototype.slice.call(arguments);
            var callback = args.pop();
            var key = hasher.apply(null, args);
            if (key in memo) {
                callback.apply(null, memo[key]);
            }
            else if (key in queues) {
                queues[key].push(callback);
            }
            else {
                queues[key] = [callback];
                fn.apply(null, args.concat([function () {
                    memo[key] = arguments;
                    var q = queues[key];
                    delete queues[key];
                    for (var i = 0, l = q.length; i < l; i++) {
                      q[i].apply(null, arguments);
                    }
                }]));
            }
        };
        memoized.memo = memo;
        memoized.unmemoized = fn;
        return memoized;
    };

    async.unmemoize = function (fn) {
      return function () {
        return (fn.unmemoized || fn).apply(null, arguments);
      };
    };

    async.times = function (count, iterator, callback) {
        var counter = [];
        for (var i = 0; i < count; i++) {
            counter.push(i);
        }
        return async.map(counter, iterator, callback);
    };

    async.timesSeries = function (count, iterator, callback) {
        var counter = [];
        for (var i = 0; i < count; i++) {
            counter.push(i);
        }
        return async.mapSeries(counter, iterator, callback);
    };

    async.compose = function (/* functions... */) {
        var fns = Array.prototype.reverse.call(arguments);
        return function () {
            var that = this;
            var args = Array.prototype.slice.call(arguments);
            var callback = args.pop();
            async.reduce(fns, args, function (newargs, fn, cb) {
                fn.apply(that, newargs.concat([function () {
                    var err = arguments[0];
                    var nextargs = Array.prototype.slice.call(arguments, 1);
                    cb(err, nextargs);
                }]))
            },
            function (err, results) {
                callback.apply(that, [err].concat(results));
            });
        };
    };

    var _applyEach = function (eachfn, fns /*args...*/) {
        var go = function () {
            var that = this;
            var args = Array.prototype.slice.call(arguments);
            var callback = args.pop();
            return eachfn(fns, function (fn, cb) {
                fn.apply(that, args.concat([cb]));
            },
            callback);
        };
        if (arguments.length > 2) {
            var args = Array.prototype.slice.call(arguments, 2);
            return go.apply(this, args);
        }
        else {
            return go;
        }
    };
    async.applyEach = doParallel(_applyEach);
    async.applyEachSeries = doSeries(_applyEach);

    async.forever = function (fn, callback) {
        function next(err) {
            if (err) {
                if (callback) {
                    return callback(err);
                }
                throw err;
            }
            fn(next);
        }
        next();
    };

    // AMD / RequireJS
    if (typeof define !== 'undefined' && define.amd) {
        define([], function () {
            return async;
        });
    }
    // Node.js
    else if (typeof module !== 'undefined' && module.exports) {
        module.exports = async;
    }
    // included directly via <script> tag
    else {
        root.async = async;
    }

}());
/*
 Copyright (c) 2012 Nevins Bartolomeo <nevins.bartolomeo@gmail.com>
 Copyright (c) 2012 Shane Girish <shaneGirish@gmail.com>
 Copyright (c) 2013 Daniel Wirtz <dcode@dcode.io>

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.
 3. The name of the author may not be used to endorse or promote products
 derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @license bcrypt.js (c) 2013 Daniel Wirtz <dcode@dcode.io>
 * Released under the Apache License, Version 2.0
 * see: https://github.com/dcodeIO/bcrypt.js for details
 */
(function(global) {

    /**
     * @type {Array.<string>}
     * @const
     * @private
     **/
    var BASE64_CODE = ['.', '/', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
        'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
        'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8',
        '9'];
    
    /**
     * @type {Array.<number>}
     * @const
     * @private
     **/
    var BASE64_INDEX = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 1,
        54, 55, 56, 57, 58, 59, 60, 61, 62, 63, -1, -1, -1, -1, -1, -1, -1,
        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 23, 24, 25, 26, 27, -1, -1, -1, -1, -1, -1, 28, 29, 30, 31,
        32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, 52, 53, -1, -1, -1, -1, -1];
    
    /**
     * Length-delimited base64 encoder and decoder.
     * @type {Object.<string,function(string, number)>}
     * @private
     */
    var base64 = {};
    
    /**
     * Encodes a byte array to base64 with up to len bytes of input.
     * @param {Array.<number>} b Byte array
     * @param {number} len Maximum input length
     * @returns {string}
     * @private
     */
    base64.encode = function(b, len) {
        var off = 0;
        var rs = [];
        var c1;
        var c2;
        if (len <= 0 || len > b.length) {
            throw(new Error("Invalid 'len': "+len));
        }
        while (off < len) {
            c1 = b[off++] & 0xff;
            rs.push(BASE64_CODE[(c1 >> 2) & 0x3f]);
            c1 = (c1 & 0x03) << 4;
            if (off >= len) {
                rs.push(BASE64_CODE[c1 & 0x3f]);
                break;
            }
            c2 = b[off++] & 0xff;
            c1 |= (c2 >> 4) & 0x0f;
            rs.push(BASE64_CODE[c1 & 0x3f]);
            c1 = (c2 & 0x0f) << 2;
            if (off >= len) {
                rs.push(BASE64_CODE[c1 & 0x3f]);
                break;
            }
            c2 = b[off++] & 0xff;
            c1 |= (c2 >> 6) & 0x03;
            rs.push(BASE64_CODE[c1 & 0x3f]);
            rs.push(BASE64_CODE[c2 & 0x3f]);
        }
        return rs.join('');
    };
    
    /**
     * Decodes a base64 encoded string to up to len bytes of output.
     * @param {string} s String to decode
     * @param {number} len Maximum output length
     * @returns {Array.<number>}
     * @private
     */
    base64.decode = function(s, len) {
        var off = 0;
        var slen = s.length;
        var olen = 0;
        var rs = [];
        var c1, c2, c3, c4, o, code;
        if (len <= 0) throw(new Error("Illegal 'len': "+len));
        while (off < slen - 1 && olen < len) {
            code = s.charCodeAt(off++);
            c1 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
            code = s.charCodeAt(off++);
            c2 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
            if (c1 == -1 || c2 == -1) {
                break;
            }
            o = (c1 << 2) >>> 0;
            o |= (c2 & 0x30) >> 4;
            rs.push(String.fromCharCode(o));
            if (++olen >= len || off >= slen) {
                break;
            }
            code = s.charCodeAt(off++);
            c3 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
            if (c3 == -1) {
                break;
            }
            o = ((c2 & 0x0f) << 4) >>> 0;
            o |= (c3 & 0x3c) >> 2;
            rs.push(String.fromCharCode(o));
            if (++olen >= len || off >= slen) {
                break;
            }
            code = s.charCodeAt(off++);
            c4 = code < BASE64_INDEX.length ? BASE64_INDEX[code] : -1;
            o = ((c3 & 0x03) << 6) >>> 0;
            o |= c4;
            rs.push(String.fromCharCode(o));
            ++olen;
        }
        var res = [];
        for (off = 0; off<olen; off++) {
            res.push(rs[off].charCodeAt(0));
        }
        return res;
    };    
    /**
     * bcrypt namespace.
     * @type {Object.<string,*>}
     */
    var bcrypt = {};

    /**
     * @type {number}
     * @const
     * @private
     */
    var BCRYPT_SALT_LEN = 16;

    /**
     * @type {number}
     * @const
     * @private
     */
    var GENSALT_DEFAULT_LOG2_ROUNDS = 10;

    /**
     * @type {number}
     * @const
     * @private
     */
    var BLOWFISH_NUM_ROUNDS = 16;

    /**
     * @type {number}
     * @const
     * @private
     */
    var MAX_EXECUTION_TIME = 100;

    /**
     * @type {Array.<number>}
     * @const
     * @private
     */
    var P_ORIG = [
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822,
        0x299f31d0, 0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377,
        0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5,
        0xb5470917, 0x9216d5d9, 0x8979fb1b
    ];

    /**
     * @type {Array.<number>}
     * @const
     * @private
     */
    var S_ORIG = [
        0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed,
        0x6a267e96, 0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7,
        0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69, 0xa458fea3,
        0xf4933d7e, 0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee,
        0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013, 0xc5d1b023,
        0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
        0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda,
        0x55605c60, 0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440,
        0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af,
        0x7c72e993, 0xb3ee1411, 0x636fbc2a, 0x2ba9c55d, 0x741831f6,
        0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c, 0x7a325381,
        0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193,
        0x61d809cc, 0xfb21a991, 0x487cac60, 0x5dec8032, 0xef845d5d,
        0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
        0x0f6d6ff3, 0x83f44239, 0x2e0b4482, 0xa4842004, 0x69c8f04a,
        0x9e1f9b5e, 0x21c66842, 0xf6e96c9a, 0x670c9c61, 0xabd388f0,
        0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c,
        0x137a3be4, 0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176,
        0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4, 0x7d84a5c3,
        0x3b8b5ebe, 0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6,
        0x4ed3aa62, 0x363f7706, 0x1bfedf72, 0x429b023d, 0x37d0d724,
        0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b,
        0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b, 0x976ce0bd,
        0x04c006ba, 0xc1a94fb6, 0x409f60c4, 0x5e5c9ec2, 0x196a2463,
        0x68fb6faf, 0x3e6c53b5, 0x1339b2eb, 0x3b52ec6f, 0x6dfc511f,
        0x9b30952c, 0xcc814544, 0xaf5ebd09, 0xbee3d004, 0xde334afd,
        0x660f2807, 0x192e4bb3, 0xc0cba857, 0x45c8740f, 0xd20b5f39,
        0xb9d3fbdb, 0x5579c0bd, 0x1a60320a, 0xd6a100c6, 0x402c7279,
        0x679f25fe, 0xfb1fa3cc, 0x8ea5e9f8, 0xdb3222f8, 0x3c7516df,
        0xfd616b15, 0x2f501ec8, 0xad0552ab, 0x323db5fa, 0xfd238760,
        0x53317b48, 0x3e00df82, 0x9e5c57bb, 0xca6f8ca0, 0x1a87562e,
        0xdf1769db, 0xd542a8f6, 0x287effc3, 0xac6732c6, 0x8c4f5573,
        0x695b27b0, 0xbbca58c8, 0xe1ffa35d, 0xb8f011a0, 0x10fa3d98,
        0xfd2183b8, 0x4afcb56c, 0x2dd1d35b, 0x9a53e479, 0xb6f84565,
        0xd28e49bc, 0x4bfb9790, 0xe1ddf2da, 0xa4cb7e33, 0x62fb1341,
        0xcee4c6e8, 0xef20cada, 0x36774c01, 0xd07e9efe, 0x2bf11fb4,
        0x95dbda4d, 0xae909198, 0xeaad8e71, 0x6b93d5a0, 0xd08ed1d0,
        0xafc725e0, 0x8e3c5b2f, 0x8e7594b7, 0x8ff6e2fb, 0xf2122b64,
        0x8888b812, 0x900df01c, 0x4fad5ea0, 0x688fc31c, 0xd1cff191,
        0xb3a8c1ad, 0x2f2f2218, 0xbe0e1777, 0xea752dfe, 0x8b021fa1,
        0xe5a0cc0f, 0xb56f74e8, 0x18acf3d6, 0xce89e299, 0xb4a84fe0,
        0xfd13e0b7, 0x7cc43b81, 0xd2ada8d9, 0x165fa266, 0x80957705,
        0x93cc7314, 0x211a1477, 0xe6ad2065, 0x77b5fa86, 0xc75442f5,
        0xfb9d35cf, 0xebcdaf0c, 0x7b3e89a0, 0xd6411bd3, 0xae1e7e49,
        0x00250e2d, 0x2071b35e, 0x226800bb, 0x57b8e0af, 0x2464369b,
        0xf009b91e, 0x5563911d, 0x59dfa6aa, 0x78c14389, 0xd95a537f,
        0x207d5ba2, 0x02e5b9c5, 0x83260376, 0x6295cfa9, 0x11c81968,
        0x4e734a41, 0xb3472dca, 0x7b14a94a, 0x1b510052, 0x9a532915,
        0xd60f573f, 0xbc9bc6e4, 0x2b60a476, 0x81e67400, 0x08ba6fb5,
        0x571be91f, 0xf296ec6b, 0x2a0dd915, 0xb6636521, 0xe7b9f9b6,
        0xff34052e, 0xc5855664, 0x53b02d5d, 0xa99f8fa1, 0x08ba4799,
        0x6e85076a, 0x4b7a70e9, 0xb5b32944, 0xdb75092e, 0xc4192623,
        0xad6ea6b0, 0x49a7df7d, 0x9cee60b8, 0x8fedb266, 0xecaa8c71,
        0x699a17ff, 0x5664526c, 0xc2b19ee1, 0x193602a5, 0x75094c29,
        0xa0591340, 0xe4183a3e, 0x3f54989a, 0x5b429d65, 0x6b8fe4d6,
        0x99f73fd6, 0xa1d29c07, 0xefe830f5, 0x4d2d38e6, 0xf0255dc1,
        0x4cdd2086, 0x8470eb26, 0x6382e9c6, 0x021ecc5e, 0x09686b3f,
        0x3ebaefc9, 0x3c971814, 0x6b6a70a1, 0x687f3584, 0x52a0e286,
        0xb79c5305, 0xaa500737, 0x3e07841c, 0x7fdeae5c, 0x8e7d44ec,
        0x5716f2b8, 0xb03ada37, 0xf0500c0d, 0xf01c1f04, 0x0200b3ff,
        0xae0cf51a, 0x3cb574b2, 0x25837a58, 0xdc0921bd, 0xd19113f9,
        0x7ca92ff6, 0x94324773, 0x22f54701, 0x3ae5e581, 0x37c2dadc,
        0xc8b57634, 0x9af3dda7, 0xa9446146, 0x0fd0030e, 0xecc8c73e,
        0xa4751e41, 0xe238cd99, 0x3bea0e2f, 0x3280bba1, 0x183eb331,
        0x4e548b38, 0x4f6db908, 0x6f420d03, 0xf60a04bf, 0x2cb81290,
        0x24977c79, 0x5679b072, 0xbcaf89af, 0xde9a771f, 0xd9930810,
        0xb38bae12, 0xdccf3f2e, 0x5512721f, 0x2e6b7124, 0x501adde6,
        0x9f84cd87, 0x7a584718, 0x7408da17, 0xbc9f9abc, 0xe94b7d8c,
        0xec7aec3a, 0xdb851dfa, 0x63094366, 0xc464c3d2, 0xef1c1847,
        0x3215d908, 0xdd433b37, 0x24c2ba16, 0x12a14d43, 0x2a65c451,
        0x50940002, 0x133ae4dd, 0x71dff89e, 0x10314e55, 0x81ac77d6,
        0x5f11199b, 0x043556f1, 0xd7a3c76b, 0x3c11183b, 0x5924a509,
        0xf28fe6ed, 0x97f1fbfa, 0x9ebabf2c, 0x1e153c6e, 0x86e34570,
        0xeae96fb1, 0x860e5e0a, 0x5a3e2ab3, 0x771fe71c, 0x4e3d06fa,
        0x2965dcb9, 0x99e71d0f, 0x803e89d6, 0x5266c825, 0x2e4cc978,
        0x9c10b36a, 0xc6150eba, 0x94e2ea78, 0xa5fc3c53, 0x1e0a2df4,
        0xf2f74ea7, 0x361d2b3d, 0x1939260f, 0x19c27960, 0x5223a708,
        0xf71312b6, 0xebadfe6e, 0xeac31f66, 0xe3bc4595, 0xa67bc883,
        0xb17f37d1, 0x018cff28, 0xc332ddef, 0xbe6c5aa5, 0x65582185,
        0x68ab9802, 0xeecea50f, 0xdb2f953b, 0x2aef7dad, 0x5b6e2f84,
        0x1521b628, 0x29076170, 0xecdd4775, 0x619f1510, 0x13cca830,
        0xeb61bd96, 0x0334fe1e, 0xaa0363cf, 0xb5735c90, 0x4c70a239,
        0xd59e9e0b, 0xcbaade14, 0xeecc86bc, 0x60622ca7, 0x9cab5cab,
        0xb2f3846e, 0x648b1eaf, 0x19bdf0ca, 0xa02369b9, 0x655abb50,
        0x40685a32, 0x3c2ab4b3, 0x319ee9d5, 0xc021b8f7, 0x9b540b19,
        0x875fa099, 0x95f7997e, 0x623d7da8, 0xf837889a, 0x97e32d77,
        0x11ed935f, 0x16681281, 0x0e358829, 0xc7e61fd6, 0x96dedfa1,
        0x7858ba99, 0x57f584a5, 0x1b227263, 0x9b83c3ff, 0x1ac24696,
        0xcdb30aeb, 0x532e3054, 0x8fd948e4, 0x6dbc3128, 0x58ebf2ef,
        0x34c6ffea, 0xfe28ed61, 0xee7c3c73, 0x5d4a14d9, 0xe864b7e3,
        0x42105d14, 0x203e13e0, 0x45eee2b6, 0xa3aaabea, 0xdb6c4f15,
        0xfacb4fd0, 0xc742f442, 0xef6abbb5, 0x654f3b1d, 0x41cd2105,
        0xd81e799e, 0x86854dc7, 0xe44b476a, 0x3d816250, 0xcf62a1f2,
        0x5b8d2646, 0xfc8883a0, 0xc1c7b6a3, 0x7f1524c3, 0x69cb7492,
        0x47848a0b, 0x5692b285, 0x095bbf00, 0xad19489d, 0x1462b174,
        0x23820e00, 0x58428d2a, 0x0c55f5ea, 0x1dadf43e, 0x233f7061,
        0x3372f092, 0x8d937e41, 0xd65fecf1, 0x6c223bdb, 0x7cde3759,
        0xcbee7460, 0x4085f2a7, 0xce77326e, 0xa6078084, 0x19f8509e,
        0xe8efd855, 0x61d99735, 0xa969a7aa, 0xc50c06c2, 0x5a04abfc,
        0x800bcadc, 0x9e447a2e, 0xc3453484, 0xfdd56705, 0x0e1e9ec9,
        0xdb73dbd3, 0x105588cd, 0x675fda79, 0xe3674340, 0xc5c43465,
        0x713e38d8, 0x3d28f89e, 0xf16dff20, 0x153e21e7, 0x8fb03d4a,
        0xe6e39f2b, 0xdb83adf7, 0xe93d5a68, 0x948140f7, 0xf64c261c,
        0x94692934, 0x411520f7, 0x7602d4f7, 0xbcf46b2e, 0xd4a20068,
        0xd4082471, 0x3320f46a, 0x43b7d4b7, 0x500061af, 0x1e39f62e,
        0x97244546, 0x14214f74, 0xbf8b8840, 0x4d95fc1d, 0x96b591af,
        0x70f4ddd3, 0x66a02f45, 0xbfbc09ec, 0x03bd9785, 0x7fac6dd0,
        0x31cb8504, 0x96eb27b3, 0x55fd3941, 0xda2547e6, 0xabca0a9a,
        0x28507825, 0x530429f4, 0x0a2c86da, 0xe9b66dfb, 0x68dc1462,
        0xd7486900, 0x680ec0a4, 0x27a18dee, 0x4f3ffea2, 0xe887ad8c,
        0xb58ce006, 0x7af4d6b6, 0xaace1e7c, 0xd3375fec, 0xce78a399,
        0x406b2a42, 0x20fe9e35, 0xd9f385b9, 0xee39d7ab, 0x3b124e8b,
        0x1dc9faf7, 0x4b6d1856, 0x26a36631, 0xeae397b2, 0x3a6efa74,
        0xdd5b4332, 0x6841e7f7, 0xca7820fb, 0xfb0af54e, 0xd8feb397,
        0x454056ac, 0xba489527, 0x55533a3a, 0x20838d87, 0xfe6ba9b7,
        0xd096954b, 0x55a867bc, 0xa1159a58, 0xcca92963, 0x99e1db33,
        0xa62a4a56, 0x3f3125f9, 0x5ef47e1c, 0x9029317c, 0xfdf8e802,
        0x04272f70, 0x80bb155c, 0x05282ce3, 0x95c11548, 0xe4c66d22,
        0x48c1133f, 0xc70f86dc, 0x07f9c9ee, 0x41041f0f, 0x404779a4,
        0x5d886e17, 0x325f51eb, 0xd59bc0d1, 0xf2bcc18f, 0x41113564,
        0x257b7834, 0x602a9c60, 0xdff8e8a3, 0x1f636c1b, 0x0e12b4c2,
        0x02e1329e, 0xaf664fd1, 0xcad18115, 0x6b2395e0, 0x333e92e1,
        0x3b240b62, 0xeebeb922, 0x85b2a20e, 0xe6ba0d99, 0xde720c8c,
        0x2da2f728, 0xd0127845, 0x95b794fd, 0x647d0862, 0xe7ccf5f0,
        0x5449a36f, 0x877d48fa, 0xc39dfd27, 0xf33e8d1e, 0x0a476341,
        0x992eff74, 0x3a6f6eab, 0xf4f8fd37, 0xa812dc60, 0xa1ebddf8,
        0x991be14c, 0xdb6e6b0d, 0xc67b5510, 0x6d672c37, 0x2765d43b,
        0xdcd0e804, 0xf1290dc7, 0xcc00ffa3, 0xb5390f92, 0x690fed0b,
        0x667b9ffb, 0xcedb7d9c, 0xa091cf0b, 0xd9155ea3, 0xbb132f88,
        0x515bad24, 0x7b9479bf, 0x763bd6eb, 0x37392eb3, 0xcc115979,
        0x8026e297, 0xf42e312d, 0x6842ada7, 0xc66a2b3b, 0x12754ccc,
        0x782ef11c, 0x6a124237, 0xb79251e7, 0x06a1bbe6, 0x4bfb6350,
        0x1a6b1018, 0x11caedfa, 0x3d25bdd8, 0xe2e1c3c9, 0x44421659,
        0x0a121386, 0xd90cec6e, 0xd5abea2a, 0x64af674e, 0xda86a85f,
        0xbebfe988, 0x64e4c3fe, 0x9dbc8057, 0xf0f7c086, 0x60787bf8,
        0x6003604d, 0xd1fd8346, 0xf6381fb0, 0x7745ae04, 0xd736fccc,
        0x83426b33, 0xf01eab71, 0xb0804187, 0x3c005e5f, 0x77a057be,
        0xbde8ae24, 0x55464299, 0xbf582e61, 0x4e58f48f, 0xf2ddfda2,
        0xf474ef38, 0x8789bdc2, 0x5366f9c3, 0xc8b38e74, 0xb475f255,
        0x46fcd9b9, 0x7aeb2661, 0x8b1ddf84, 0x846a0e79, 0x915f95e2,
        0x466e598e, 0x20b45770, 0x8cd55591, 0xc902de4c, 0xb90bace1,
        0xbb8205d0, 0x11a86248, 0x7574a99e, 0xb77f19b6, 0xe0a9dc09,
        0x662d09a1, 0xc4324633, 0xe85a1f02, 0x09f0be8c, 0x4a99a025,
        0x1d6efe10, 0x1ab93d1d, 0x0ba5a4df, 0xa186f20f, 0x2868f169,
        0xdcb7da83, 0x573906fe, 0xa1e2ce9b, 0x4fcd7f52, 0x50115e01,
        0xa70683fa, 0xa002b5c4, 0x0de6d027, 0x9af88c27, 0x773f8641,
        0xc3604c06, 0x61a806b5, 0xf0177a28, 0xc0f586e0, 0x006058aa,
        0x30dc7d62, 0x11e69ed7, 0x2338ea63, 0x53c2dd94, 0xc2c21634,
        0xbbcbee56, 0x90bcb6de, 0xebfc7da1, 0xce591d76, 0x6f05e409,
        0x4b7c0188, 0x39720a3d, 0x7c927c24, 0x86e3725f, 0x724d9db9,
        0x1ac15bb4, 0xd39eb8fc, 0xed545578, 0x08fca5b5, 0xd83d7cd3,
        0x4dad0fc4, 0x1e50ef5e, 0xb161e6f8, 0xa28514d9, 0x6c51133c,
        0x6fd5c7e7, 0x56e14ec4, 0x362abfce, 0xddc6c837, 0xd79a3234,
        0x92638212, 0x670efa8e, 0x406000e0, 0x3a39ce37, 0xd3faf5cf,
        0xabc27737, 0x5ac52d1b, 0x5cb0679e, 0x4fa33742, 0xd3822740,
        0x99bc9bbe, 0xd5118e9d, 0xbf0f7315, 0xd62d1c7e, 0xc700c47b,
        0xb78c1b6b, 0x21a19045, 0xb26eb1be, 0x6a366eb4, 0x5748ab2f,
        0xbc946e79, 0xc6a376d2, 0x6549c2c8, 0x530ff8ee, 0x468dde7d,
        0xd5730a1d, 0x4cd04dc6, 0x2939bbdb, 0xa9ba4650, 0xac9526e8,
        0xbe5ee304, 0xa1fad5f0, 0x6a2d519a, 0x63ef8ce2, 0x9a86ee22,
        0xc089c2b8, 0x43242ef6, 0xa51e03aa, 0x9cf2d0a4, 0x83c061ba,
        0x9be96a4d, 0x8fe51550, 0xba645bd6, 0x2826a2f9, 0xa73a3ae1,
        0x4ba99586, 0xef5562e9, 0xc72fefd3, 0xf752f7da, 0x3f046f69,
        0x77fa0a59, 0x80e4a915, 0x87b08601, 0x9b09e6ad, 0x3b3ee593,
        0xe990fd5a, 0x9e34d797, 0x2cf0b7d9, 0x022b8b51, 0x96d5ac3a,
        0x017da67d, 0xd1cf3ed6, 0x7c7d2d28, 0x1f9f25cf, 0xadf2b89b,
        0x5ad6b472, 0x5a88f54c, 0xe029ac71, 0xe019a5e6, 0x47b0acfd,
        0xed93fa9b, 0xe8d3c48d, 0x283b57cc, 0xf8d56629, 0x79132e28,
        0x785f0191, 0xed756055, 0xf7960e44, 0xe3d35e8c, 0x15056dd4,
        0x88f46dba, 0x03a16125, 0x0564f0bd, 0xc3eb9e15, 0x3c9057a2,
        0x97271aec, 0xa93a072a, 0x1b3f6d9b, 0x1e6321f5, 0xf59c66fb,
        0x26dcf319, 0x7533d928, 0xb155fdf5, 0x03563482, 0x8aba3cbb,
        0x28517711, 0xc20ad9f8, 0xabcc5167, 0xccad925f, 0x4de81751,
        0x3830dc8e, 0x379d5862, 0x9320f991, 0xea7a90c2, 0xfb3e7bce,
        0x5121ce64, 0x774fbe32, 0xa8b6e37e, 0xc3293d46, 0x48de5369,
        0x6413e680, 0xa2ae0810, 0xdd6db224, 0x69852dfd, 0x09072166,
        0xb39a460a, 0x6445c0dd, 0x586cdecf, 0x1c20c8ae, 0x5bbef7dd,
        0x1b588d40, 0xccd2017f, 0x6bb4e3bb, 0xdda26a7e, 0x3a59ff45,
        0x3e350a44, 0xbcb4cdd5, 0x72eacea8, 0xfa6484bb, 0x8d6612ae,
        0xbf3c6f47, 0xd29be463, 0x542f5d9e, 0xaec2771b, 0xf64e6370,
        0x740e0d8d, 0xe75b1357, 0xf8721671, 0xaf537d5d, 0x4040cb08,
        0x4eb4e2cc, 0x34d2466a, 0x0115af84, 0xe1b00428, 0x95983a1d,
        0x06b89fb4, 0xce6ea048, 0x6f3f3b82, 0x3520ab82, 0x011a1d4b,
        0x277227f8, 0x611560b1, 0xe7933fdc, 0xbb3a792b, 0x344525bd,
        0xa08839e1, 0x51ce794b, 0x2f32c9b7, 0xa01fbac9, 0xe01cc87e,
        0xbcc7d1f6, 0xcf0111c3, 0xa1e8aac7, 0x1a908749, 0xd44fbd9a,
        0xd0dadecb, 0xd50ada38, 0x0339c32a, 0xc6913667, 0x8df9317c,
        0xe0b12b4f, 0xf79e59b7, 0x43f5bb3a, 0xf2d519ff, 0x27d9459c,
        0xbf97222c, 0x15e6fc2a, 0x0f91fc71, 0x9b941525, 0xfae59361,
        0xceb69ceb, 0xc2a86459, 0x12baa8d1, 0xb6c1075e, 0xe3056a0c,
        0x10d25065, 0xcb03a442, 0xe0ec6e0e, 0x1698db3b, 0x4c98a0be,
        0x3278e964, 0x9f1f9532, 0xe0d392df, 0xd3a0342b, 0x8971f21e,
        0x1b0a7441, 0x4ba3348c, 0xc5be7120, 0xc37632d8, 0xdf359f8d,
        0x9b992f2e, 0xe60b6f47, 0x0fe3f11d, 0xe54cda54, 0x1edad891,
        0xce6279cf, 0xcd3e7e6f, 0x1618b166, 0xfd2c1d05, 0x848fd2c5,
        0xf6fb2299, 0xf523f357, 0xa6327623, 0x93a83531, 0x56cccd02,
        0xacf08162, 0x5a75ebb5, 0x6e163697, 0x88d273cc, 0xde966292,
        0x81b949d0, 0x4c50901b, 0x71c65614, 0xe6c6c7bd, 0x327a140a,
        0x45e1d006, 0xc3f27b9a, 0xc9aa53fd, 0x62a80f00, 0xbb25bfe2,
        0x35bdd2f6, 0x71126905, 0xb2040222, 0xb6cbcf7c, 0xcd769c2b,
        0x53113ec0, 0x1640e3d3, 0x38abbd60, 0x2547adf0, 0xba38209c,
        0xf746ce76, 0x77afa1c5, 0x20756060, 0x85cbfe4e, 0x8ae88dd8,
        0x7aaaf9b0, 0x4cf9aa7e, 0x1948c25c, 0x02fb8a8c, 0x01c36ae4,
        0xd6ebe1f9, 0x90d4f869, 0xa65cdea0, 0x3f09252d, 0xc208e69f,
        0xb74e6132, 0xce77e25b, 0x578fdfe3, 0x3ac372e6
    ];

    /**
     * @type {Array.<number>}
     * @const
     * @private
     */
    var C_ORIG = [
        0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944,
        0x6f756274
    ];

    /**
     * @param {Array.<number>} lr
     * @param {number} off
     * @param {Array.<number>} P
     * @param {Array.<number>} S
     * @returns {Array.<number>}
     * @private
     */
    function _encipher(lr, off, P, S) { // This is our bottleneck: 1714/1905 ticks / 90% - see profile.txt
        var n;
        var l = lr[off];
        var r = lr[off + 1];

        l ^= P[0];
        for (var i=0; i<=BLOWFISH_NUM_ROUNDS-2;) {
            // Feistel substitution on left word
            n  = S[(l >> 24) & 0xff];
            n += S[0x100 | ((l >> 16) & 0xff)];
            n ^= S[0x200 | ((l >> 8) & 0xff)];
            n += S[0x300 | (l & 0xff)];
            r ^= n ^ P[++i];

            // Feistel substitution on right word
            n  = S[(r >> 24) & 0xff];
            n += S[0x100 | ((r >> 16) & 0xff)];
            n ^= S[0x200 | ((r >> 8) & 0xff)];
            n += S[0x300 | (r & 0xff)];
            l ^= n ^ P[++i];
        }
        lr[off] = r ^ P[BLOWFISH_NUM_ROUNDS + 1];
        lr[off + 1] = l;
        return lr;
    }

    /**
     * @param {Array.<number>} data
     * @param {number} offp
     * @returns {{key: number, offp: number}}
     * @private
     */
    function _streamtoword(data, offp) {
        var i;
        var word = 0;
        for (i = 0; i < 4; i++) {
            word = (word << 8) | (data[offp] & 0xff);
            offp = (offp + 1) % data.length;
        }
        return { key: word, offp: offp };
    }

    /**
     * @param {Array.<number>} key
     * @param {Array.<number>} P
     * @param {Array.<number>} S
     * @private
     */
    function _key(key, P, S) {
        var offset = 0;
        var lr = new Array(0x00000000, 0x00000000);
        var plen = P.length;
        var slen = S.length;
        for (var i = 0; i < plen; i++) {
            var sw = _streamtoword(key, offset);
            offset = sw.offp;
            P[i] = P[i] ^ sw.key;
        }
        for (i = 0; i < plen; i += 2) {
            lr = _encipher(lr, 0, P, S);
            P[i] = lr[0];
            P[i + 1] = lr[1];
        }

        for (i = 0; i < slen; i += 2) {
            lr = _encipher(lr, 0, P, S);
            S[i] = lr[0];
            S[i + 1] = lr[1];
        }
    }

    /**
     * Expensive key schedule Blowfish.
     * @param {Array.<number>} data
     * @param {Array.<number>} key
     * @param {Array.<number>} P
     * @param {Array.<number>} S
     * @private
     */
    function _ekskey(data, key, P, S) {
        var offp = 0;
        var lr = new Array(0x00000000, 0x00000000);
        var plen = P.length;
        var slen = S.length;
        var sw;
        for (var i = 0; i < plen; i++) {
            sw = _streamtoword(key, offp);
            offp = sw.offp;
            P[i] = P[i] ^ sw.key;
        }
        offp = 0;
        for (i = 0; i < plen; i += 2) {
            sw = _streamtoword(data, offp);
            offp = sw.offp;
            lr[0] ^= sw.key;

            sw = _streamtoword(data, offp);
            offp = sw.offp;
            lr[1] ^= sw.key;

            lr = _encipher(lr, 0, P, S);
            P[i] = lr[0];
            P[i + 1] = lr[1];
        }
        for (i = 0; i < slen; i += 2) {
            sw = _streamtoword(data, offp);
            offp = sw.offp;
            lr[0] ^= sw.key;

            sw = _streamtoword(data, offp);
            offp = sw.offp;
            lr[1] ^= sw.key;

            lr = _encipher(lr, 0, P, S);
            S[i] = lr[0];
            S[i + 1] = lr[1];
        }
    }

    /**
     * Continues with the callback on the next tick.
     * @param {function(...[*])} callback Callback to execute
     * @private
     */
    function _nextTick(callback) {
        if (typeof process !== 'undefined' && typeof process.nextTick === 'function') {
            if (typeof setImmediate === 'function') {
                setImmediate(callback);
            } else {
                process.nextTick(callback);
            }
        } else {
            setTimeout(callback, 0);
        }
    }

    /**
     * Internaly crypts a string.
     * @param {Array.<number>} b Bytes to crypt
     * @param {Array.<number>} salt Salt bytes to use
     * @param {number} rounds Number of rounds
     * @param {function(Error, Array.<number>)=} callback Callback receiving the error, if any, and the resulting bytes. If
     *  omitted, the operation will be performed synchronously.
     * @returns {Array.<number>} Resulting bytes or if callback has been omitted, otherwise null
     * @private
     */
    function _crypt(b, salt, rounds, callback) {
        var cdata = C_ORIG.slice();
        var clen = cdata.length;

        // Validate
        if (rounds < 4 || rounds > 31) {
            throw(new Error("Illegal number of rounds: "+rounds));
        }
        if (salt.length != BCRYPT_SALT_LEN) {
            throw(new Error("Illegal salt length: "+salt.length+" != "+BCRYPT_SALT_LEN));
        }
        rounds = 1 << rounds;
        var P = P_ORIG.slice();
        var S = S_ORIG.slice();

        _ekskey(salt, b, P, S);

        var i = 0, j;

        /**
         * Calcualtes the next round.
         * @returns {Array.<number>} Resulting array if callback has been omitted, otherwise null
         * @private
         */
        function next() {
            if (i < rounds) {
                var start = new Date();
                for (; i < rounds;) {
                    i = i + 1;
                    _key(b, P, S);
                    _key(salt, P, S);
                    if (Date.now() - start > MAX_EXECUTION_TIME) { // TODO (dcode): Is this necessary?
                        break;
                    }
                }
            } else {
                for (i = 0; i < 64; i++) {
                    for (j = 0; j < (clen >> 1); j++) {
                        _encipher(cdata, j << 1, P, S);
                    }
                }
                var ret = [];
                for (i = 0; i < clen; i++) {
                    ret.push(((cdata[i] >> 24) & 0xff) >>> 0);
                    ret.push(((cdata[i] >> 16) & 0xff) >>> 0);
                    ret.push(((cdata[i] >> 8) & 0xff) >>> 0);
                    ret.push((cdata[i] & 0xff) >>> 0);
                }
                if (callback) {
                    callback(null, ret);
                    return null;
                } else {
                    return ret;
                }
            }
            if (callback) {
                _nextTick(next);
            }
            return null;
        }

        // Async
        if (typeof callback !== 'undefined') {
            next();
            return null;
         // Sync
        } else {
            var res;
            while (true) {
                if ((res = next()) !== null) {
                    return res;
                }
            }
        }
    }

    function _stringToBytes ( str ) {
        var ch, st, re = [];
        for (var i = 0; i < str.length; i++ ) {
            ch = str.charCodeAt(i);
            st = [];
            do {
                st.push( ch & 0xFF );
                ch = ch >> 8;
            } while (ch);
            re = re.concat( st.reverse() );
        }
        return re;
    }

    /**
     * Internally hashes a string.
     * @param {string} s String to hash
     * @param {?string} salt Salt to use, actually never null
     * @param {function(Error, ?string)=} callback Callback receiving the error, if any, and the resulting hash. If omitted,
     *  hashing is perormed synchronously.
     * @returns {?string} Resulting hash if callback has been omitted, else null
     * @private
     */
    function _hash(s, salt, callback) {

        // Validate the salt
        var minor, offset;
        if (salt.charAt(0) != '$' || salt.charAt(1) != '2') {
            throw(new Error("Invalid salt version: "+salt.substring(0,2)));
        }
        if (salt.charAt(2) == '$') {
            minor = String.fromCharCode(0);
            offset = 3;
        } else {
            minor = salt.charAt(2);
            if (minor != 'a' || salt.charAt(3) != '$') {
                throw(new Error("Invalid salt revision: "+salt.substring(2,4)));
            }
            offset = 4;
        }

        // Extract number of rounds
        if (salt.charAt(offset + 2) > '$') {
            throw(new Error("Missing salt rounds"));
        }
        var r1 = parseInt(salt.substring(offset, offset + 1), 10) * 10;
        var r2 = parseInt(salt.substring(offset + 1, offset + 2), 10);
        var rounds = r1 + r2;
        var real_salt = salt.substring(offset + 3, offset + 25);
        s += minor >= 'a' ? "\000" : "";

        var passwordb = _stringToBytes(s);
        var saltb = [];
        saltb = base64.decode(real_salt, BCRYPT_SALT_LEN);

        /**
         * Finishs hashing.
         * @param {Array.<number>} bytes Byte array
         * @returns {string}
         * @private
         */
        function finish(bytes) {
            var res = [];
            res.push("$2");
            if (minor >= 'a') res.push(minor);
            res.push("$");
            if (rounds < 10) res.push("0");
            res.push(rounds.toString());
            res.push("$");
            res.push(base64.encode(saltb, saltb.length));
            res.push(base64.encode(bytes, C_ORIG.length * 4 - 1));
            return res.join('');
        }

        // Sync
        if (typeof callback == 'undefined') {
            return finish(_crypt(passwordb, saltb, rounds));

            // Async
        } else {
            _crypt(passwordb, saltb, rounds, function(err, bytes) {
                if (err) {
                    callback(err, null);
                } else {
                    callback(null, finish(bytes));
                }
            });
            return null;
        }
    }

    /**
     * Generates cryptographically secure random bytes.
     * @param {number} len Number of bytes to generate
     * @returns {Array.<number>}
     * @private
     */
    function _randomBytes(len) {
        // node.js, see: http://nodejs.org/api/crypto.html
        if (typeof module !== 'undefined' && module.exports) {
            var crypto = require("crypto");
            return crypto.randomBytes(len);
            
        // Browser, see: http://www.w3.org/TR/WebCryptoAPI/
        } else {
            var array = new Uint32Array(len);
            if (global.crypto && typeof global.crypto.getRandomValues === 'function') {
                global.crypto.getRandomValues(array);
            } else if (typeof _getRandomValues === 'function') {
                _getRandomValues(array);
            } else {
                throw(new Error("Failed to generate random values: Web Crypto API not available / no polyfill set"));
            }
            return Array.prototype.slice.call(array);
        }
    }

    /**
     * Internally generates a salt.
     * @param {number} rounds Number of rounds to use
     * @returns {string} Salt
     * @throws {Error} If anything goes wrong
     * @private
     */
    function _gensalt(rounds) {
        rounds = rounds || 10;
        if (rounds < 4 || rounds > 31) {
            throw(new Error("Illegal number of rounds: "+rounds));
        }
        var salt = [];
        salt.push("$2a$");
        if (rounds < GENSALT_DEFAULT_LOG2_ROUNDS) salt.push("0");
        salt.push(rounds.toString());
        salt.push('$');
        try {
            salt.push(base64.encode(_randomBytes(BCRYPT_SALT_LEN), BCRYPT_SALT_LEN));
            return salt.join('');
        } catch(err) {
            throw(err);
        }
    }
    
    // crypto.getRandomValues polyfill to use
    var _getRandomValues = null;
    
    /**
     * Sets the polyfill that should be used if window.crypto.getRandomValues is not available.
     * @param {function(Uint32Array)} getRandomValues The actual implementation
     * @expose
     */
    bcrypt.setRandomPolyfill = function(getRandomValues) {
        _getRandomValues = getRandomValues;
    };

    /**
     * Synchronously generates a salt.
     * @param {number=} rounds Number of rounds to use, defaults to 10 if omitted
     * @param {number=} seed_length Not supported.
     * @returns {string} Resulting salt
     * @expose
     */
    bcrypt.genSaltSync = function(rounds, seed_length) {
        if (!rounds) rounds = 10;
        return _gensalt(rounds);
    };

    /**
     * Asynchronously generates a salt.
     * @param {(number|function(Error, ?string))=} rounds Number of rounds to use, defaults to 10 if omitted
     * @param {(number|function(Error, ?string))=} seed_length Not supported.
     * @param {function(Error, ?string)=} callback Callback receiving the error, if any, and the resulting salt
     * @expose
     */
    bcrypt.genSalt = function(rounds, seed_length, callback) {
        if (typeof seed_length == 'function') {
            callback = seed_length;
            seed_length = -1; // Not supported.
        }
        var rnd; // Hello closure
        if (typeof rounds == 'function') {
            callback = rounds;
            rnd = GENSALT_DEFAULT_LOG2_ROUNDS;
        } else {
            rnd = parseInt(rounds, 10);
        }
        if (typeof callback != 'function') {
            throw(new Error("Illegal or missing 'callback': "+callback));
        }
        _nextTick(function() { // Pretty thin, but salting is fast enough
            try {
                var res = bcrypt.genSaltSync(rnd);
                callback(null, res);
            } catch(err) {
                callback(err, null);
            }
        });
    };

    /**
     * Synchronously generates a hash for the given string.
     * @param {string} s String to hash
     * @param {(number|string)=} salt Salt length to generate or salt to use, default to 10
     * @returns {?string} Resulting hash, actually never null
     * @expose
     */
    bcrypt.hashSync = function(s, salt) {
        if (!salt) salt = GENSALT_DEFAULT_LOG2_ROUNDS;
        if (typeof salt == 'number') {
            salt = bcrypt.genSaltSync(salt);
        }
        return _hash(s, salt);
    };

    /**
     * Asynchronously generates a hash for the given string.
     * @param {string} s String to hash
     * @param {number|string} salt Salt length to generate or salt to use
     * @param {function(Error, ?string)} callback Callback receiving the error, if any, and the resulting hash
     * @expose
     */
    bcrypt.hash = function(s, salt, callback) {
        if (typeof callback != 'function') {
            throw(new Error("Illegal 'callback': "+callback));
        }
        if (typeof salt == 'number') {
            bcrypt.genSalt(salt, function(err, salt) {
                _hash(s, salt, callback);
            });
        } else {
            _hash(s, salt, callback);
        }
    };

    /**
     * Synchronously tests a string against a hash.
     * @param {string} s String to compare
     * @param {string} hash Hash to test against
     * @returns {boolean} true if matching, otherwise false
     * @throws {Error} If an argument is illegal
     * @expose
     */
    bcrypt.compareSync = function(s, hash) {
        if(typeof s != "string" ||  typeof hash != "string") {
            throw(new Error("Illegal argument types: "+(typeof s)+', '+(typeof hash)));
        }
        if(hash.length != 60) {
            throw(new Error("Illegal hash length: "+hash.length+" != 60"));
        }
        var comp = bcrypt.hashSync(s, hash.substr(0, hash.length-31));
        var same = comp.length == hash.length;
        var max_length = (comp.length < hash.length) ? comp.length : hash.length;

        // to prevent timing attacks, should check entire string
        // don't exit after found to be false
        for (var i = 0; i < max_length; ++i) {
            if (comp.length >= i && hash.length >= i && comp[i] != hash[i]) {
                same = false;
            }
        }
        return same;
    };

    /**
     * Asynchronously compares the given data against the given hash.
     * @param {string} s Data to compare
     * @param {string} hash Data to be compared to
     * @param {function(Error, boolean)} callback Callback receiving the error, if any, otherwise the result
     * @throws {Error} If the callback argument is invalid
     * @expose
     */
    bcrypt.compare = function(s, hash, callback) {
        if (typeof callback != 'function') {
            throw(new Error("Illegal 'callback': "+callback));
        }
        bcrypt.hash(s, hash.substr(0, 29), function(err, comp) {
            callback(err, hash === comp);
        });
    };

    /**
     * Gets the number of rounds used to encrypt the specified hash.
     * @param {string} hash Hash to extract the used number of rounds from
     * @returns {number} Number of rounds used
     * @throws {Error} If hash is not a string
     * @expose
     */
    bcrypt.getRounds = function(hash) {
        if(typeof hash != "string") {
            throw(new Error("Illegal type of 'hash': "+(typeof hash)));
        }
        return parseInt(hash.split("$")[2], 10);
    };

    /**
     * Gets the salt portion from a hash.
     * @param {string} hash Hash to extract the salt from
     * @returns {string} Extracted salt part portion
     * @throws {Error} If `hash` is not a string or otherwise invalid
     * @expose
     */
    bcrypt.getSalt = function(hash) {
        if (typeof hash != 'string') {
            throw(new Error("Illegal type of 'hash': "+(typeof hash)));
        }
        if(hash.length != 60) {
            throw(new Error("Illegal hash length: "+hash.length+" != 60"));
        }
        return hash.substring(0, 29);
    };

    // Enable module loading if available
    if (typeof module != 'undefined' && module["exports"]) { // CommonJS
        module["exports"] = bcrypt;
    } else if (typeof define != 'undefined' && define["amd"]) { // AMD
        define("bcrypt", function() { return bcrypt; });
    } else { // Shim
        if (!global["dcodeIO"]) {
            global["dcodeIO"] = {};
        }
        global["dcodeIO"]["bcrypt"] = bcrypt;
    }
    
})(this);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Cam Pedersen <cam@campedersen.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
*/

(function () {

self.isomerize = function (obj, dependencies) {
  return;
  // if we don't have access to web workers,
  // just run everything in the main thread
  if (!window.Worker) {
    return;
  }

  var code = '';

  if (typeof dependencies == 'string') {
    code += 'window = document = self; self.worker = true;\n';
    code += 'document.documentElement = { style: [] };\n'; // fix for socket.io
    code += 'importScripts(\'' + dependencies + '\');\n';
  } else {
    for (var i in dependencies) {
      var name = dependencies[i];
      var dep = window[name];
      code += toSource(dep, name);
    }
  }

  code += toSource(obj, 'original');
  code += '(' + isomerExternal.toString() + ')();';

  var blob = new Blob([ code ], { type: 'application/javascript' });
  var worker = new Worker(URL.createObjectURL(blob));
  var listeners = {};

  worker.onmessage = function (e) {
    var data = JSON.parse(e.data);

    if (!listeners[data.time]) {
      return;
    }

    listeners[data.time].apply(listeners[data.time], data.args);
  };

  for (var i in obj) {
    if (typeof obj[i] == 'function') {
      obj[i] = overrideLocalMethod(i);
    }
  }

  function overrideLocalMethod (methodName) {
    return function isomerProxy () {
      var args = [].slice.call(arguments);
      var callback = args.pop();
      var now = +new Date();
      listeners[now] = callback;

      worker.postMessage(JSON.stringify({
        name: methodName,
        time: now,
        args: args
      }));
    }
  }
}

function isomerExternal () {
  onmessage = function (e) {
    var data = JSON.parse(e.data);
    var args = data.args;

    args.push(function () {
      var args = [].slice.call(arguments);
      postMessage(JSON.stringify({
        time: data.time,
        args: args
      }));
    });

    original[data.name].apply(original, args);
  }
}

function toSource (obj, name) {
  var code = '';

  if (name) {
    code += 'var ' + name + ' = ';
  }

  if (typeof obj == 'function') {
    code += obj.toString();
  } else {
    code += JSON.stringify(obj);
  }

  code += ';\n';

  for (var i in obj) {
    if (typeof obj[i] != 'function') {
      continue;
    }

    if (name) {
      code += name + '.' + i + ' = ';
    }

    code += obj[i].toString() + ';\n';
  }

  for (var i in obj.prototype) {
    if (name) {
      code += name + '.prototype.' + i + ' = ';
    }

    if (typeof obj.prototype[i] == 'function') {
      code += obj.prototype[i].toString() + ';\n';
    } else if (typeof obj.prototype[i] == 'object') {
      code += JSON.stringify(obj.prototype[i]) + ';\n';
    }
  }

  return code;
}


})();
/*
*   Json Diff Patch
*   ---------------
*   https://github.com/benjamine/JsonDiffPatch
*   by Benjamin Eidelman - beneidel@gmail.com
*/(function(){"use strict";var e={};typeof t!="undefined"&&(e=t);var t=e;e.version="0.0.7",e.config={textDiffMinLength:60,detectArrayMove:!0,includeValueOnArrayMove:!1};var n={diff:function(t,n,r,i){var s=0,o=0,u,a,f=t.length,l=n.length,c,h=[],p=[],d=typeof r=="function"?function(e,t,n,i){if(e===t)return!0;if(typeof e!="object"||typeof t!="object")return!1;var s,o;return typeof n=="number"?(s=h[n],typeof s=="undefined"&&(h[n]=s=r(e))):s=r(e),typeof i=="number"?(o=p[i],typeof o=="undefined"&&(p[i]=o=r(t))):o=r(t),s===o}:function(e,t){return e===t},v=function(e,r){return d(t[e],n[r],e,r)},m=function(e,r){if(!i)return;if(typeof t[e]!="object"||typeof n[r]!="object")return;var s=i(t[e],n[r]);if(typeof s=="undefined")return;c||(c={_t:"a"}),c[r]=s};while(s<f&&s<l&&v(s,s))m(s,s),s++;while(o+s<f&&o+s<l&&v(f-1-o,l-1-o))m(f-1-o,l-1-o),o++;if(s+o===f){if(f===l)return c;c=c||{_t:"a"};for(u=s;u<l-o;u++)c[u]=[n[u]];return c}if(s+o===l){c=c||{_t:"a"};for(u=s;u<f-o;u++)c["_"+u]=[t[u],0,0];return c}var g=this.lcs(t.slice(s,f-o),n.slice(s,l-o),{areTheSameByIndex:function(e,t){return v(e+s,t+s)}});c=c||{_t:"a"};var y=[];for(u=s;u<f-o;u++)g.indices1.indexOf(u-s)<0&&(c["_"+u]=[t[u],0,0],y.push(u));var b=y.length;for(u=s;u<l-o;u++){var w=g.indices2.indexOf(u-s);if(w<0){var E=!1;if(e.config.detectArrayMove&&b>0)for(a=0;a<b;a++)if(v(y[a],u)){c["_"+y[a]].splice(1,2,u,3),e.config.includeValueOnArrayMove||(c["_"+y[a]][0]=""),m(y[a],u),y.splice(a,1),E=!0;break}E||(c[u]=[n[u]])}else m(g.indices1[w]+s,g.indices2[w]+s)}return c},getArrayIndexBefore:function(e,t){var n,r=t;for(var s in e)if(e.hasOwnProperty(s)&&i(e[s])){s.slice(0,1)==="_"?n=parseInt(s.slice(1),10):n=parseInt(s,10);if(e[s].length===1){if(n<t)r--;else if(n===t)return-1}else if(e[s].length===3)if(e[s][2]===0)n<=t&&r++;else if(e[s][2]===3){n<=t&&r++;if(e[s][1]>t)r--;else if(e[s][1]===t)return n}}return r},patch:function(e,t,n,r){var i,s,o=function(e,t){return e-t},u=function(e){return function(t,n){return t[e]-n[e]}},a=[],f=[],l=[];for(i in t)if(i!=="_t")if(i[0]=="_"){if(t[i][2]!==0&&t[i][2]!==3)throw new Error("only removal or move can be applied at original array indices, invalid diff type: "+t[i][2]);a.push(parseInt(i.slice(1),10))}else t[i].length===1?f.push({index:parseInt(i,10),value:t[i][0]}):l.push({index:parseInt(i,10),diff:t[i]});a=a.sort(o);for(i=a.length-1;i>=0;i--){s=a[i];var c=t["_"+s],h=e.splice(s,1)[0];c[2]===3&&f.push({index:c[1],value:h})}f=f.sort(u("index"));var p=f.length;for(i=0;i<p;i++){var d=f[i];e.splice(d.index,0,d.value)}var v=l.length;if(v>0){if(typeof n!="function")throw new Error("to patch items in the array an objectInnerPatch function must be provided");for(i=0;i<v;i++){var m=l[i];n(e,m.index.toString(),m.diff,r)}}return e},lcs:function(e,t,n){n.areTheSameByIndex=n.areTheSameByIndex||function(n,r){return e[n]===t[r]};var r=this.lengthMatrix(e,t,n),i=this.backtrack(r,e,t,e.length,t.length);return typeof e=="string"&&typeof t=="string"&&(i.sequence=i.sequence.join("")),i},lengthMatrix:function(e,t,n){var r=e.length,i=t.length,s,o,u=[r+1];for(s=0;s<r+1;s++){u[s]=[i+1];for(o=0;o<i+1;o++)u[s][o]=0}u.options=n;for(s=1;s<r+1;s++)for(o=1;o<i+1;o++)n.areTheSameByIndex(s-1,o-1)?u[s][o]=u[s-1][o-1]+1:u[s][o]=Math.max(u[s-1][o],u[s][o-1]);return u},backtrack:function(e,t,n,r,i){if(r===0||i===0)return{sequence:[],indices1:[],indices2:[]};if(e.options.areTheSameByIndex(r-1,i-1)){var s=this.backtrack(e,t,n,r-1,i-1);return s.sequence.push(t[r-1]),s.indices1.push(r-1),s.indices2.push(i-1),s}return e[r][i-1]>e[r-1][i]?this.backtrack(e,t,n,r,i-1):this.backtrack(e,t,n,r-1,i)}};e.sequenceDiffer=n,e.dateReviver=function(e,t){var n;if(typeof t=="string"){n=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}(?:\.\d*)?)(Z|([+\-])(\d{2}):(\d{2}))$/.exec(t);if(n)return new Date(Date.UTC(+n[1],+n[2]-1,+n[3],+n[4],+n[5],+n[6]))}return t};var r=function(){var t;e.config.diff_match_patch&&(t=new e.config.diff_match_patch.diff_match_patch),typeof diff_match_patch!="undefined"&&(typeof diff_match_patch=="function"?t=new diff_match_patch:typeof diff_match_patch=="object"&&typeof diff_match_patch.diff_match_patch=="function"&&(t=new diff_match_patch.diff_match_patch));if(t)return e.config.textDiff=function(e,n){return t.patch_toText(t.patch_make(e,n))},e.config.textPatch=function(e,n){var r=t.patch_apply(t.patch_fromText(n),e);for(var i=0;i<r[1].length;i++)if(!r[1][i])throw new Error("text patch failed");return r[0]},!0},i=e.isArray=typeof Array.isArray=="function"?Array.isArray:function(e){return typeof e=="object"&&e instanceof Array},s=e.isDate=function(e){return e instanceof Date||Object.prototype.toString.call(e)==="[object Date]"},o=function(t,r){return n.diff(t,r,e.config.objectHash,e.diff)},u=function(e,t){var n,r,i,s;s=function(i){r=a(e[i],t[i]),typeof r!="undefined"&&(typeof n=="undefined"&&(n={}),n[i]=r)};for(i in t)t.hasOwnProperty(i)&&s(i);for(i in e)e.hasOwnProperty(i)&&typeof t[i]=="undefined"&&s(i);return n},a=e.diff=function(t,n){var a,f,l,c,h;if(t===n)return;if(t!==t&&n!==n)return;a=typeof n,f=typeof t,l=n===null,c=t===null,f=="object"&&s(t)&&(f="date");if(a=="object"&&s(n)){a="date";if(f=="date"&&t.getTime()===n.getTime())return}if(l||c||a=="undefined"||a!=f||a=="number"||f=="number"||a=="boolean"||f=="boolean"||a=="string"||f=="string"||a=="date"||f=="date"||a==="object"&&i(n)!=i(t)){h=[];if(typeof t!="undefined")if(typeof n!="undefined"){var p=a=="string"&&f=="string"&&Math.min(t.length,n.length)>e.config.textDiffMinLength;p&&!e.config.textDiff&&r(),p&&e.config.textDiff?h.push(e.config.textDiff(t,n),0,2):(h.push(t),h.push(n))}else h.push(t),h.push(0,0);else h.push(n);return h}return i(n)?o(t,n):u(t,n)},f=function(e,t){return i(e)?e[parseInt(t,10)]:e[t]};e.getByKey=f;var l=function(e,t,n){if(i(e)&&e._key){var r=e._key;typeof e._key!="function"&&(r=function(t){return t[e._key]});for(var s=0;s<e.length;s++)if(r(e[s])===t){typeof n=="undefined"?(e.splice(s,1),s--):e[s]=n;return}typeof n!="undefined"&&e.push(n);return}typeof n=="undefined"?i(e)?e.splice(t,1):delete e[t]:e[t]=n},c=function(t){return e.config.textDiffReverse||(e.config.textDiffReverse=function(e){var t,n,r,i,s,o=null,u=/^@@ +\-(\d+),(\d+) +\+(\d+),(\d+) +@@$/,a,f,l,c=function(){f!==null&&(r[f]="-"+r[f].slice(1)),l!==null&&(r[l]="+"+r[l].slice(1),f!==null&&(s=r[f],r[f]=r[l],r[l]=s)),r[a]="@@ -"+o[3]+","+o[4]+" +"+o[1]+","+o[2]+" @@",o=null,a=null,f=null,l=null};r=e.split("\n");for(t=0,n=r.length;t<n;t++){i=r[t];var h=i.slice(0,1);h==="@"?(o!==null,o=u.exec(i),a=t,f=null,l=null,r[a]="@@ -"+o[3]+","+o[4]+" +"+o[1]+","+o[2]+" @@"):h=="+"?(f=t,r[t]="-"+r[t].slice(1)):h=="-"&&(l=t,r[t]="+"+r[t].slice(1))}return o!==null,r.join("\n")}),e.config.textDiffReverse(t)},h=e.reverse=function(e){var t,r;if(typeof e=="undefined")return;if(e===null)return null;if(typeof e=="object"&&!s(e)){if(i(e)){if(e.length<3)return e.length===1?[e[0],0,0]:[e[1],e[0]];if(e[2]===0)return[e[0]];if(e[2]===2)return[c(e[0]),0,2];throw new Error("invalid diff type")}r={};if(e._t==="a"){for(t in e)if(e.hasOwnProperty(t)&&t!=="_t"){var o,u=t;t.slice(0,1)==="_"?o=parseInt(t.slice(1),10):o=parseInt(t,10);if(i(e[t]))if(e[t].length===1)u="_"+o;else if(e[t].length===2)u=n.getArrayIndexBefore(e,o);else if(e[t][2]===0)u=o.toString();else{if(e[t][2]===3){u="_"+e[t][1],r[u]=[e[t][0],o,3];continue}u=n.getArrayIndexBefore(e,o)}else u=n.getArrayIndexBefore(e,o);r[u]=h(e[t])}r._t="a"}else for(t in e)e.hasOwnProperty(t)&&(r[t]=h(e[t]));return r}return typeof e=="string"&&e.slice(0,2)==="@@"?c(e):e},p=e.patch=function(s,o,u,a){var c,h,d="",v;typeof o!="string"?(a=u,u=o,o=null):typeof s!="object"&&(o=null),a&&(d+=a),d+="/",o!==null&&(d+=o);if(typeof u=="object")if(i(u)){if(u.length<3)return h=u[u.length-1],o!==null&&l(s,o,h),h;if(u[2]!==0){if(u[2]===2){e.config.textPatch||r();if(!e.config.textPatch)throw new Error("textPatch function not found");try{h=e.config.textPatch(f(s,o),u[0])}catch(m){throw new Error('cannot apply patch at "'+d+'": '+m)}return o!==null&&l(s,o,h),h}throw u[2]===3?new Error("Not implemented diff type: "+u[2]):new Error("invalid diff type: "+u[2])}if(o===null)return;l(s,o)}else if(u._t=="a"){v=o===null?s:f(s,o);if(typeof v!="object"||!i(v))throw new Error('cannot apply patch at "'+d+'": array expected');n.patch(v,u,t.patch,d)}else{v=o===null?s:f(s,o);if(typeof v!="object"||i(v))throw new Error('cannot apply patch at "'+d+'": object expected');for(c in u)u.hasOwnProperty(c)&&p(v,c,u[c],d)}return s},d=e.unpatch=function(e,t,n,r){return typeof t!="string"?p(e,h(t),n):p(e,t,h(n),r)};typeof require=="function"&&typeof exports=="object"&&typeof module=="object"?module.exports=e:typeof define=="function"&&define.amd?define(e):window.jsondiffpatch=e})();;(function(){

/**
 * Require the given path.
 *
 * @param {String} path
 * @return {Object} exports
 * @api public
 */

function require(path, parent, orig) {
  var resolved = require.resolve(path);

  // lookup failed
  if (null == resolved) {
    orig = orig || path;
    parent = parent || 'root';
    var err = new Error('Failed to require "' + orig + '" from "' + parent + '"');
    err.path = orig;
    err.parent = parent;
    err.require = true;
    throw err;
  }

  var module = require.modules[resolved];

  // perform real require()
  // by invoking the module's
  // registered function
  if (!module._resolving && !module.exports) {
    var mod = {};
    mod.exports = {};
    mod.client = mod.component = true;
    module._resolving = true;
    module.call(this, mod.exports, require.relative(resolved), mod);
    delete module._resolving;
    module.exports = mod.exports;
  }

  return module.exports;
}

/**
 * Registered modules.
 */

require.modules = {};

/**
 * Registered aliases.
 */

require.aliases = {};

/**
 * Resolve `path`.
 *
 * Lookup:
 *
 *   - PATH/index.js
 *   - PATH.js
 *   - PATH
 *
 * @param {String} path
 * @return {String} path or null
 * @api private
 */

require.resolve = function(path) {
  if (path.charAt(0) === '/') path = path.slice(1);

  var paths = [
    path,
    path + '.js',
    path + '.json',
    path + '/index.js',
    path + '/index.json'
  ];

  for (var i = 0; i < paths.length; i++) {
    var path = paths[i];
    if (require.modules.hasOwnProperty(path)) return path;
    if (require.aliases.hasOwnProperty(path)) return require.aliases[path];
  }
};

/**
 * Normalize `path` relative to the current path.
 *
 * @param {String} curr
 * @param {String} path
 * @return {String}
 * @api private
 */

require.normalize = function(curr, path) {
  var segs = [];

  if ('.' != path.charAt(0)) return path;

  curr = curr.split('/');
  path = path.split('/');

  for (var i = 0; i < path.length; ++i) {
    if ('..' == path[i]) {
      curr.pop();
    } else if ('.' != path[i] && '' != path[i]) {
      segs.push(path[i]);
    }
  }

  return curr.concat(segs).join('/');
};

/**
 * Register module at `path` with callback `definition`.
 *
 * @param {String} path
 * @param {Function} definition
 * @api private
 */

require.register = function(path, definition) {
  require.modules[path] = definition;
};

/**
 * Alias a module definition.
 *
 * @param {String} from
 * @param {String} to
 * @api private
 */

require.alias = function(from, to) {
  if (!require.modules.hasOwnProperty(from)) {
    throw new Error('Failed to alias "' + from + '", it does not exist');
  }
  require.aliases[to] = from;
};

/**
 * Return a require function relative to the `parent` path.
 *
 * @param {String} parent
 * @return {Function}
 * @api private
 */

require.relative = function(parent) {
  var p = require.normalize(parent, '..');

  /**
   * lastIndexOf helper.
   */

  function lastIndexOf(arr, obj) {
    var i = arr.length;
    while (i--) {
      if (arr[i] === obj) return i;
    }
    return -1;
  }

  /**
   * The relative require() itself.
   */

  function localRequire(path) {
    var resolved = localRequire.resolve(path);
    return require(resolved, parent, path);
  }

  /**
   * Resolve relative to the parent.
   */

  localRequire.resolve = function(path) {
    var c = path.charAt(0);
    if ('/' == c) return path.slice(1);
    if ('.' == c) return require.normalize(p, path);

    // resolve deps by returning
    // the dep in the nearest "deps"
    // directory
    var segs = parent.split('/');
    var i = lastIndexOf(segs, 'deps') + 1;
    if (!i) i = 0;
    path = segs.slice(0, i + 1).join('/') + '/deps/' + path;
    return path;
  };

  /**
   * Check if module is defined at `path`.
   */

  localRequire.exists = function(path) {
    return require.modules.hasOwnProperty(localRequire.resolve(path));
  };

  return localRequire;
};
require.register("component-emitter/index.js", function(exports, require, module){

/**
 * Expose `Emitter`.
 */

module.exports = Emitter;

/**
 * Initialize a new `Emitter`.
 *
 * @api public
 */

function Emitter(obj) {
  if (obj) return mixin(obj);
};

/**
 * Mixin the emitter properties.
 *
 * @param {Object} obj
 * @return {Object}
 * @api private
 */

function mixin(obj) {
  for (var key in Emitter.prototype) {
    obj[key] = Emitter.prototype[key];
  }
  return obj;
}

/**
 * Listen on the given `event` with `fn`.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.on =
Emitter.prototype.addEventListener = function(event, fn){
  this._callbacks = this._callbacks || {};
  (this._callbacks[event] = this._callbacks[event] || [])
    .push(fn);
  return this;
};

/**
 * Adds an `event` listener that will be invoked a single
 * time then automatically removed.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.once = function(event, fn){
  var self = this;
  this._callbacks = this._callbacks || {};

  function on() {
    self.off(event, on);
    fn.apply(this, arguments);
  }

  on.fn = fn;
  this.on(event, on);
  return this;
};

/**
 * Remove the given callback for `event` or all
 * registered callbacks.
 *
 * @param {String} event
 * @param {Function} fn
 * @return {Emitter}
 * @api public
 */

Emitter.prototype.off =
Emitter.prototype.removeListener =
Emitter.prototype.removeAllListeners =
Emitter.prototype.removeEventListener = function(event, fn){
  this._callbacks = this._callbacks || {};

  // all
  if (0 == arguments.length) {
    this._callbacks = {};
    return this;
  }

  // specific event
  var callbacks = this._callbacks[event];
  if (!callbacks) return this;

  // remove all handlers
  if (1 == arguments.length) {
    delete this._callbacks[event];
    return this;
  }

  // remove specific handler
  var cb;
  for (var i = 0; i < callbacks.length; i++) {
    cb = callbacks[i];
    if (cb === fn || cb.fn === fn) {
      callbacks.splice(i, 1);
      break;
    }
  }
  return this;
};

/**
 * Emit `event` with the given args.
 *
 * @param {String} event
 * @param {Mixed} ...
 * @return {Emitter}
 */

Emitter.prototype.emit = function(event){
  this._callbacks = this._callbacks || {};
  var args = [].slice.call(arguments, 1)
    , callbacks = this._callbacks[event];

  if (callbacks) {
    callbacks = callbacks.slice(0);
    for (var i = 0, len = callbacks.length; i < len; ++i) {
      callbacks[i].apply(this, args);
    }
  }

  return this;
};

/**
 * Return array of callbacks for `event`.
 *
 * @param {String} event
 * @return {Array}
 * @api public
 */

Emitter.prototype.listeners = function(event){
  this._callbacks = this._callbacks || {};
  return this._callbacks[event] || [];
};

/**
 * Check if this emitter has `event` handlers.
 *
 * @param {String} event
 * @return {Boolean}
 * @api public
 */

Emitter.prototype.hasListeners = function(event){
  return !! this.listeners(event).length;
};

});
require.register("RedVentures-reduce/index.js", function(exports, require, module){

/**
 * Reduce `arr` with `fn`.
 *
 * @param {Array} arr
 * @param {Function} fn
 * @param {Mixed} initial
 *
 * TODO: combatible error handling?
 */

module.exports = function(arr, fn, initial){  
  var idx = 0;
  var len = arr.length;
  var curr = arguments.length == 3
    ? initial
    : arr[idx++];

  while (idx < len) {
    curr = fn.call(null, curr, arr[idx], ++idx, arr);
  }
  
  return curr;
};
});
require.register("superagent/lib/client.js", function(exports, require, module){
/**
 * Module dependencies.
 */

var Emitter = require('emitter');
var reduce = require('reduce');

/**
 * Root reference for iframes.
 */

var root = 'undefined' == typeof window
  ? this
  : window;

/**
 * Noop.
 */

function noop(){};

/**
 * Check if `obj` is a host object,
 * we don't want to serialize these :)
 *
 * TODO: future proof, move to compoent land
 *
 * @param {Object} obj
 * @return {Boolean}
 * @api private
 */

function isHost(obj) {
  var str = {}.toString.call(obj);

  switch (str) {
    case '[object File]':
    case '[object Blob]':
    case '[object FormData]':
      return true;
    default:
      return false;
  }
}

/**
 * Determine XHR.
 */

function getXHR() {
  if (root.XMLHttpRequest
    && ('file:' != root.location.protocol || !root.ActiveXObject)) {
    return new XMLHttpRequest;
  } else {
    try { return new ActiveXObject('Microsoft.XMLHTTP'); } catch(e) {}
    try { return new ActiveXObject('Msxml2.XMLHTTP.6.0'); } catch(e) {}
    try { return new ActiveXObject('Msxml2.XMLHTTP.3.0'); } catch(e) {}
    try { return new ActiveXObject('Msxml2.XMLHTTP'); } catch(e) {}
  }
  return false;
}

/**
 * Removes leading and trailing whitespace, added to support IE.
 *
 * @param {String} s
 * @return {String}
 * @api private
 */

var trim = ''.trim
  ? function(s) { return s.trim(); }
  : function(s) { return s.replace(/(^\s*|\s*$)/g, ''); };

/**
 * Check if `obj` is an object.
 *
 * @param {Object} obj
 * @return {Boolean}
 * @api private
 */

function isObject(obj) {
  return obj === Object(obj);
}

/**
 * Serialize the given `obj`.
 *
 * @param {Object} obj
 * @return {String}
 * @api private
 */

function serialize(obj) {
  if (!isObject(obj)) return obj;
  var pairs = [];
  for (var key in obj) {
    if (null != obj[key]) {
      pairs.push(encodeURIComponent(key)
        + '=' + encodeURIComponent(obj[key]));
    }
  }
  return pairs.join('&');
}

/**
 * Expose serialization method.
 */

 request.serializeObject = serialize;

 /**
  * Parse the given x-www-form-urlencoded `str`.
  *
  * @param {String} str
  * @return {Object}
  * @api private
  */

function parseString(str) {
  var obj = {};
  var pairs = str.split('&');
  var parts;
  var pair;

  for (var i = 0, len = pairs.length; i < len; ++i) {
    pair = pairs[i];
    parts = pair.split('=');
    obj[decodeURIComponent(parts[0])] = decodeURIComponent(parts[1]);
  }

  return obj;
}

/**
 * Expose parser.
 */

request.parseString = parseString;

/**
 * Default MIME type map.
 *
 *     superagent.types.xml = 'application/xml';
 *
 */

request.types = {
  html: 'text/html',
  json: 'application/json',
  xml: 'application/xml',
  urlencoded: 'application/x-www-form-urlencoded',
  'form': 'application/x-www-form-urlencoded',
  'form-data': 'application/x-www-form-urlencoded'
};

/**
 * Default serialization map.
 *
 *     superagent.serialize['application/xml'] = function(obj){
 *       return 'generated xml here';
 *     };
 *
 */

 request.serialize = {
   'application/x-www-form-urlencoded': serialize,
   'application/json': JSON.stringify
 };

 /**
  * Default parsers.
  *
  *     superagent.parse['application/xml'] = function(str){
  *       return { object parsed from str };
  *     };
  *
  */

request.parse = {
  'application/x-www-form-urlencoded': parseString,
  'application/json': JSON.parse
};

/**
 * Parse the given header `str` into
 * an object containing the mapped fields.
 *
 * @param {String} str
 * @return {Object}
 * @api private
 */

function parseHeader(str) {
  var lines = str.split(/\r?\n/);
  var fields = {};
  var index;
  var line;
  var field;
  var val;

  lines.pop(); // trailing CRLF

  for (var i = 0, len = lines.length; i < len; ++i) {
    line = lines[i];
    index = line.indexOf(':');
    field = line.slice(0, index).toLowerCase();
    val = trim(line.slice(index + 1));
    fields[field] = val;
  }

  return fields;
}

/**
 * Return the mime type for the given `str`.
 *
 * @param {String} str
 * @return {String}
 * @api private
 */

function type(str){
  return str.split(/ *; */).shift();
};

/**
 * Return header field parameters.
 *
 * @param {String} str
 * @return {Object}
 * @api private
 */

function params(str){
  return reduce(str.split(/ *; */), function(obj, str){
    var parts = str.split(/ *= */)
      , key = parts.shift()
      , val = parts.shift();

    if (key && val) obj[key] = val;
    return obj;
  }, {});
};

/**
 * Initialize a new `Response` with the given `xhr`.
 *
 *  - set flags (.ok, .error, etc)
 *  - parse header
 *
 * Examples:
 *
 *  Aliasing `superagent` as `request` is nice:
 *
 *      request = superagent;
 *
 *  We can use the promise-like API, or pass callbacks:
 *
 *      request.get('/').end(function(res){});
 *      request.get('/', function(res){});
 *
 *  Sending data can be chained:
 *
 *      request
 *        .post('/user')
 *        .send({ name: 'tj' })
 *        .end(function(res){});
 *
 *  Or passed to `.send()`:
 *
 *      request
 *        .post('/user')
 *        .send({ name: 'tj' }, function(res){});
 *
 *  Or passed to `.post()`:
 *
 *      request
 *        .post('/user', { name: 'tj' })
 *        .end(function(res){});
 *
 * Or further reduced to a single call for simple cases:
 *
 *      request
 *        .post('/user', { name: 'tj' }, function(res){});
 *
 * @param {XMLHTTPRequest} xhr
 * @param {Object} options
 * @api private
 */

function Response(req, options) {
  options = options || {};
  this.req = req;
  this.xhr = this.req.xhr;
  this.text = this.xhr.responseText;
  this.setStatusProperties(this.xhr.status);
  this.header = this.headers = parseHeader(this.xhr.getAllResponseHeaders());
  // getAllResponseHeaders sometimes falsely returns "" for CORS requests, but
  // getResponseHeader still works. so we get content-type even if getting
  // other headers fails.
  this.header['content-type'] = this.xhr.getResponseHeader('content-type');
  this.setHeaderProperties(this.header);
  this.body = this.req.method != 'HEAD'
    ? this.parseBody(this.text)
    : null;
}

/**
 * Get case-insensitive `field` value.
 *
 * @param {String} field
 * @return {String}
 * @api public
 */

Response.prototype.get = function(field){
  return this.header[field.toLowerCase()];
};

/**
 * Set header related properties:
 *
 *   - `.type` the content type without params
 *
 * A response of "Content-Type: text/plain; charset=utf-8"
 * will provide you with a `.type` of "text/plain".
 *
 * @param {Object} header
 * @api private
 */

Response.prototype.setHeaderProperties = function(header){
  // content-type
  var ct = this.header['content-type'] || '';
  this.type = type(ct);

  // params
  var obj = params(ct);
  for (var key in obj) this[key] = obj[key];
};

/**
 * Parse the given body `str`.
 *
 * Used for auto-parsing of bodies. Parsers
 * are defined on the `superagent.parse` object.
 *
 * @param {String} str
 * @return {Mixed}
 * @api private
 */

Response.prototype.parseBody = function(str){
  var parse = request.parse[this.type];
  return parse
    ? parse(str)
    : null;
};

/**
 * Set flags such as `.ok` based on `status`.
 *
 * For example a 2xx response will give you a `.ok` of __true__
 * whereas 5xx will be __false__ and `.error` will be __true__. The
 * `.clientError` and `.serverError` are also available to be more
 * specific, and `.statusType` is the class of error ranging from 1..5
 * sometimes useful for mapping respond colors etc.
 *
 * "sugar" properties are also defined for common cases. Currently providing:
 *
 *   - .noContent
 *   - .badRequest
 *   - .unauthorized
 *   - .notAcceptable
 *   - .notFound
 *
 * @param {Number} status
 * @api private
 */

Response.prototype.setStatusProperties = function(status){
  var type = status / 100 | 0;

  // status / class
  this.status = status;
  this.statusType = type;

  // basics
  this.info = 1 == type;
  this.ok = 2 == type;
  this.clientError = 4 == type;
  this.serverError = 5 == type;
  this.error = (4 == type || 5 == type)
    ? this.toError()
    : false;

  // sugar
  this.accepted = 202 == status;
  this.noContent = 204 == status || 1223 == status;
  this.badRequest = 400 == status;
  this.unauthorized = 401 == status;
  this.notAcceptable = 406 == status;
  this.notFound = 404 == status;
  this.forbidden = 403 == status;
};

/**
 * Return an `Error` representative of this response.
 *
 * @return {Error}
 * @api public
 */

Response.prototype.toError = function(){
  var req = this.req;
  var method = req.method;
  var path = req.path;

  var msg = 'cannot ' + method + ' ' + path + ' (' + this.status + ')';
  var err = new Error(msg);
  err.status = this.status;
  err.method = method;
  err.path = path;

  return err;
};

/**
 * Expose `Response`.
 */

request.Response = Response;

/**
 * Initialize a new `Request` with the given `method` and `url`.
 *
 * @param {String} method
 * @param {String} url
 * @api public
 */

function Request(method, url) {
  var self = this;
  Emitter.call(this);
  this._query = this._query || [];
  this.method = method;
  this.url = url;
  this.header = {};
  this._header = {};
  this.on('end', function(){
    var res = new Response(self);
    if ('HEAD' == method) res.text = null;
    self.callback(null, res);
  });
}

/**
 * Mixin `Emitter`.
 */

Emitter(Request.prototype);

/**
 * Set timeout to `ms`.
 *
 * @param {Number} ms
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.timeout = function(ms){
  this._timeout = ms;
  return this;
};

/**
 * Clear previous timeout.
 *
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.clearTimeout = function(){
  this._timeout = 0;
  clearTimeout(this._timer);
  return this;
};

/**
 * Abort the request, and clear potential timeout.
 *
 * @return {Request}
 * @api public
 */

Request.prototype.abort = function(){
  if (this.aborted) return;
  this.aborted = true;
  this.xhr.abort();
  this.clearTimeout();
  this.emit('abort');
  return this;
};

/**
 * Set header `field` to `val`, or multiple fields with one object.
 *
 * Examples:
 *
 *      req.get('/')
 *        .set('Accept', 'application/json')
 *        .set('X-API-Key', 'foobar')
 *        .end(callback);
 *
 *      req.get('/')
 *        .set({ Accept: 'application/json', 'X-API-Key': 'foobar' })
 *        .end(callback);
 *
 * @param {String|Object} field
 * @param {String} val
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.set = function(field, val){
  if (isObject(field)) {
    for (var key in field) {
      this.set(key, field[key]);
    }
    return this;
  }
  this._header[field.toLowerCase()] = val;
  this.header[field] = val;
  return this;
};

/**
 * Get case-insensitive header `field` value.
 *
 * @param {String} field
 * @return {String}
 * @api private
 */

Request.prototype.getHeader = function(field){
  return this._header[field.toLowerCase()];
};

/**
 * Set Content-Type to `type`, mapping values from `request.types`.
 *
 * Examples:
 *
 *      superagent.types.xml = 'application/xml';
 *
 *      request.post('/')
 *        .type('xml')
 *        .send(xmlstring)
 *        .end(callback);
 *
 *      request.post('/')
 *        .type('application/xml')
 *        .send(xmlstring)
 *        .end(callback);
 *
 * @param {String} type
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.type = function(type){
  this.set('Content-Type', request.types[type] || type);
  return this;
};

/**
 * Set Accept to `type`, mapping values from `request.types`.
 *
 * Examples:
 *
 *      superagent.types.json = 'application/json';
 *
 *      request.get('/agent')
 *        .accept('json')
 *        .end(callback);
 *
 *      request.get('/agent')
 *        .accept('application/json')
 *        .end(callback);
 *
 * @param {String} accept
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.accept = function(type){
  this.set('Accept', request.types[type] || type);
  return this;
};

/**
 * Set Authorization field value with `user` and `pass`.
 *
 * @param {String} user
 * @param {String} pass
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.auth = function(user, pass){
  var str = btoa(user + ':' + pass);
  this.set('Authorization', 'Basic ' + str);
  return this;
};

/**
* Add query-string `val`.
*
* Examples:
*
*   request.get('/shoes')
*     .query('size=10')
*     .query({ color: 'blue' })
*
* @param {Object|String} val
* @return {Request} for chaining
* @api public
*/

Request.prototype.query = function(val){
  if ('string' != typeof val) val = serialize(val);
  if (val) this._query.push(val);
  return this;
};

/**
 * Send `data`, defaulting the `.type()` to "json" when
 * an object is given.
 *
 * Examples:
 *
 *       // querystring
 *       request.get('/search')
 *         .end(callback)
 *
 *       // multiple data "writes"
 *       request.get('/search')
 *         .send({ search: 'query' })
 *         .send({ range: '1..5' })
 *         .send({ order: 'desc' })
 *         .end(callback)
 *
 *       // manual json
 *       request.post('/user')
 *         .type('json')
 *         .send('{"name":"tj"})
 *         .end(callback)
 *
 *       // auto json
 *       request.post('/user')
 *         .send({ name: 'tj' })
 *         .end(callback)
 *
 *       // manual x-www-form-urlencoded
 *       request.post('/user')
 *         .type('form')
 *         .send('name=tj')
 *         .end(callback)
 *
 *       // auto x-www-form-urlencoded
 *       request.post('/user')
 *         .type('form')
 *         .send({ name: 'tj' })
 *         .end(callback)
 *
 *       // defaults to x-www-form-urlencoded
  *      request.post('/user')
  *        .send('name=tobi')
  *        .send('species=ferret')
  *        .end(callback)
 *
 * @param {String|Object} data
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.send = function(data){
  var obj = isObject(data);
  var type = this.getHeader('Content-Type');

  // merge
  if (obj && isObject(this._data)) {
    for (var key in data) {
      this._data[key] = data[key];
    }
  } else if ('string' == typeof data) {
    if (!type) this.type('form');
    type = this.getHeader('Content-Type');
    if ('application/x-www-form-urlencoded' == type) {
      this._data = this._data
        ? this._data + '&' + data
        : data;
    } else {
      this._data = (this._data || '') + data;
    }
  } else {
    this._data = data;
  }

  if (!obj) return this;
  if (!type) this.type('json');
  return this;
};

/**
 * Invoke the callback with `err` and `res`
 * and handle arity check.
 *
 * @param {Error} err
 * @param {Response} res
 * @api private
 */

Request.prototype.callback = function(err, res){
  var fn = this._callback;
  if (2 == fn.length) return fn(err, res);
  if (err) return this.emit('error', err);
  fn(res);
};

/**
 * Invoke callback with x-domain error.
 *
 * @api private
 */

Request.prototype.crossDomainError = function(){
  var err = new Error('Origin is not allowed by Access-Control-Allow-Origin');
  err.crossDomain = true;
  this.callback(err);
};

/**
 * Invoke callback with timeout error.
 *
 * @api private
 */

Request.prototype.timeoutError = function(){
  var timeout = this._timeout;
  var err = new Error('timeout of ' + timeout + 'ms exceeded');
  err.timeout = timeout;
  this.callback(err);
};

/**
 * Enable transmission of cookies with x-domain requests.
 *
 * Note that for this to work the origin must not be
 * using "Access-Control-Allow-Origin" with a wildcard,
 * and also must set "Access-Control-Allow-Credentials"
 * to "true".
 *
 * @api public
 */

Request.prototype.withCredentials = function(){
  this._withCredentials = true;
  return this;
};

/**
 * Initiate request, invoking callback `fn(res)`
 * with an instanceof `Response`.
 *
 * @param {Function} fn
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.end = function(fn){
  var self = this;
  var xhr = this.xhr = getXHR();
  var query = this._query.join('&');
  var timeout = this._timeout;
  var data = this._data;

  // store callback
  this._callback = fn || noop;

  // state change
  xhr.onreadystatechange = function(){
    if (4 != xhr.readyState) return;
    if (0 == xhr.status) {
      if (self.aborted) return self.timeoutError();
      return self.crossDomainError();
    }
    self.emit('end');
  };

  // progress
  if (xhr.upload) {
    xhr.upload.onprogress = function(e){
      e.percent = e.loaded / e.total * 100;
      self.emit('progress', e);
    };
  }

  // timeout
  if (timeout && !this._timer) {
    this._timer = setTimeout(function(){
      self.abort();
    }, timeout);
  }

  // querystring
  if (query) {
    query = request.serializeObject(query);
    this.url += ~this.url.indexOf('?')
      ? '&' + query
      : '?' + query;
  }

  // initiate request
  xhr.open(this.method, this.url, true);

  // CORS
  if (this._withCredentials) xhr.withCredentials = true;

  // body
  if ('GET' != this.method && 'HEAD' != this.method && 'string' != typeof data && !isHost(data)) {
    // serialize stuff
    var serialize = request.serialize[this.getHeader('Content-Type')];
    if (serialize) data = serialize(data);
  }

  // set header fields
  for (var field in this.header) {
    if (null == this.header[field]) continue;
    xhr.setRequestHeader(field, this.header[field]);
  }

  // send stuff
  xhr.send(data);
  return this;
};

/**
 * Expose `Request`.
 */

request.Request = Request;

/**
 * Issue a request:
 *
 * Examples:
 *
 *    request('GET', '/users').end(callback)
 *    request('/users').end(callback)
 *    request('/users', callback)
 *
 * @param {String} method
 * @param {String|Function} url or callback
 * @return {Request}
 * @api public
 */

function request(method, url) {
  // callback
  if ('function' == typeof url) {
    return new Request('GET', method).end(url);
  }

  // url first
  if (1 == arguments.length) {
    return new Request('GET', method);
  }

  return new Request(method, url);
}

/**
 * GET `url` with optional callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed|Function} data or fn
 * @param {Function} fn
 * @return {Request}
 * @api public
 */

request.get = function(url, data, fn){
  var req = request('GET', url);
  if ('function' == typeof data) fn = data, data = null;
  if (data) req.query(data);
  if (fn) req.end(fn);
  return req;
};

/**
 * HEAD `url` with optional callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed|Function} data or fn
 * @param {Function} fn
 * @return {Request}
 * @api public
 */

request.head = function(url, data, fn){
  var req = request('HEAD', url);
  if ('function' == typeof data) fn = data, data = null;
  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
};

/**
 * DELETE `url` with optional callback `fn(res)`.
 *
 * @param {String} url
 * @param {Function} fn
 * @return {Request}
 * @api public
 */

request.del = function(url, fn){
  var req = request('DELETE', url);
  if (fn) req.end(fn);
  return req;
};

/**
 * PATCH `url` with optional `data` and callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed} data
 * @param {Function} fn
 * @return {Request}
 * @api public
 */

request.patch = function(url, data, fn){
  var req = request('PATCH', url);
  if ('function' == typeof data) fn = data, data = null;
  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
};

/**
 * POST `url` with optional `data` and callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed} data
 * @param {Function} fn
 * @return {Request}
 * @api public
 */

request.post = function(url, data, fn){
  var req = request('POST', url);
  if ('function' == typeof data) fn = data, data = null;
  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
};

/**
 * PUT `url` with optional `data` and callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed|Function} data or fn
 * @param {Function} fn
 * @return {Request}
 * @api public
 */

request.put = function(url, data, fn){
  var req = request('PUT', url);
  if ('function' == typeof data) fn = data, data = null;
  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
};

/**
 * Expose `request`.
 */

module.exports = request;

});




require.alias("component-emitter/index.js", "superagent/deps/emitter/index.js");
require.alias("component-emitter/index.js", "emitter/index.js");

require.alias("RedVentures-reduce/index.js", "superagent/deps/reduce/index.js");
require.alias("RedVentures-reduce/index.js", "reduce/index.js");

require.alias("superagent/lib/client.js", "superagent/index.js");if (typeof exports == "object") {
  module.exports = require("superagent");
} else if (typeof define == "function" && define.amd) {
  define(function(){ return require("superagent"); });
} else {
  this["superagent"] = require("superagent");
}})();/** @fileOverview Javascript cryptography implementation.
 *
 * Crush to remove comments, shorten variable names and
 * generally reduce transmission size.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

"use strict";
/*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
/*global document, window, escape, unescape */

/** @namespace The Stanford Javascript Crypto Library, top-level namespace. */
var sjcl = {
  /** @namespace Symmetric ciphers. */
  cipher: {},

  /** @namespace Hash functions.  Right now only SHA256 is implemented. */
  hash: {},

  /** @namespace Key exchange functions.  Right now only SRP is implemented. */
  keyexchange: {},
  
  /** @namespace Block cipher modes of operation. */
  mode: {},

  /** @namespace Miscellaneous.  HMAC and PBKDF2. */
  misc: {},
  
  /**
   * @namespace Bit array encoders and decoders.
   *
   * @description
   * The members of this namespace are functions which translate between
   * SJCL's bitArrays and other objects (usually strings).  Because it
   * isn't always clear which direction is encoding and which is decoding,
   * the method names are "fromBits" and "toBits".
   */
  codec: {},
  
  /** @namespace Exceptions. */
  exception: {
    /** @class Ciphertext is corrupt. */
    corrupt: function(message) {
      this.toString = function() { return "CORRUPT: "+this.message; };
      this.message = message;
    },
    
    /** @class Invalid parameter. */
    invalid: function(message) {
      this.toString = function() { return "INVALID: "+this.message; };
      this.message = message;
    },
    
    /** @class Bug or missing feature in SJCL. */
    bug: function(message) {
      this.toString = function() { return "BUG: "+this.message; };
      this.message = message;
    },

    /** @class Something isn't ready. */
    notReady: function(message) {
      this.toString = function() { return "NOT READY: "+this.message; };
      this.message = message;
    }
  }
};

if(typeof module != 'undefined' && module.exports){
  module.exports = sjcl;
}
/** @fileOverview Low-level AES implementation.
 *
 * This file contains a low-level implementation of AES, optimized for
 * size and for efficiency on several browsers.  It is based on
 * OpenSSL's aes_core.c, a public-domain implementation by Vincent
 * Rijmen, Antoon Bosselaers and Paulo Barreto.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Schedule out an AES key for both encryption and decryption.  This
 * is a low-level class.  Use a cipher mode to do bulk encryption.
 *
 * @constructor
 * @param {Array} key The key as an array of 4, 6 or 8 words.
 *
 * @class Advanced Encryption Standard (low-level interface)
 */
sjcl.cipher.aes = function (key) {
  if (!this._tables[0][0][0]) {
    this._precompute();
  }
  
  var i, j, tmp,
    encKey, decKey,
    sbox = this._tables[0][4], decTable = this._tables[1],
    keyLen = key.length, rcon = 1;
  
  if (keyLen !== 4 && keyLen !== 6 && keyLen !== 8) {
    throw new sjcl.exception.invalid("invalid aes key size");
  }
  
  this._key = [encKey = key.slice(0), decKey = []];
  
  // schedule encryption keys
  for (i = keyLen; i < 4 * keyLen + 28; i++) {
    tmp = encKey[i-1];
    
    // apply sbox
    if (i%keyLen === 0 || (keyLen === 8 && i%keyLen === 4)) {
      tmp = sbox[tmp>>>24]<<24 ^ sbox[tmp>>16&255]<<16 ^ sbox[tmp>>8&255]<<8 ^ sbox[tmp&255];
      
      // shift rows and add rcon
      if (i%keyLen === 0) {
        tmp = tmp<<8 ^ tmp>>>24 ^ rcon<<24;
        rcon = rcon<<1 ^ (rcon>>7)*283;
      }
    }
    
    encKey[i] = encKey[i-keyLen] ^ tmp;
  }
  
  // schedule decryption keys
  for (j = 0; i; j++, i--) {
    tmp = encKey[j&3 ? i : i - 4];
    if (i<=4 || j<4) {
      decKey[j] = tmp;
    } else {
      decKey[j] = decTable[0][sbox[tmp>>>24      ]] ^
                  decTable[1][sbox[tmp>>16  & 255]] ^
                  decTable[2][sbox[tmp>>8   & 255]] ^
                  decTable[3][sbox[tmp      & 255]];
    }
  }
};

sjcl.cipher.aes.prototype = {
  // public
  /* Something like this might appear here eventually
  name: "AES",
  blockSize: 4,
  keySizes: [4,6,8],
  */
  
  /**
   * Encrypt an array of 4 big-endian words.
   * @param {Array} data The plaintext.
   * @return {Array} The ciphertext.
   */
  encrypt:function (data) { return this._crypt(data,0); },
  
  /**
   * Decrypt an array of 4 big-endian words.
   * @param {Array} data The ciphertext.
   * @return {Array} The plaintext.
   */
  decrypt:function (data) { return this._crypt(data,1); },
  
  /**
   * The expanded S-box and inverse S-box tables.  These will be computed
   * on the client so that we don't have to send them down the wire.
   *
   * There are two tables, _tables[0] is for encryption and
   * _tables[1] is for decryption.
   *
   * The first 4 sub-tables are the expanded S-box with MixColumns.  The
   * last (_tables[01][4]) is the S-box itself.
   *
   * @private
   */
  _tables: [[[],[],[],[],[]],[[],[],[],[],[]]],

  /**
   * Expand the S-box tables.
   *
   * @private
   */
  _precompute: function () {
   var encTable = this._tables[0], decTable = this._tables[1],
       sbox = encTable[4], sboxInv = decTable[4],
       i, x, xInv, d=[], th=[], x2, x4, x8, s, tEnc, tDec;

    // Compute double and third tables
   for (i = 0; i < 256; i++) {
     th[( d[i] = i<<1 ^ (i>>7)*283 )^i]=i;
   }
   
   for (x = xInv = 0; !sbox[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
     // Compute sbox
     s = xInv ^ xInv<<1 ^ xInv<<2 ^ xInv<<3 ^ xInv<<4;
     s = s>>8 ^ s&255 ^ 99;
     sbox[x] = s;
     sboxInv[s] = x;
     
     // Compute MixColumns
     x8 = d[x4 = d[x2 = d[x]]];
     tDec = x8*0x1010101 ^ x4*0x10001 ^ x2*0x101 ^ x*0x1010100;
     tEnc = d[s]*0x101 ^ s*0x1010100;
     
     for (i = 0; i < 4; i++) {
       encTable[i][x] = tEnc = tEnc<<24 ^ tEnc>>>8;
       decTable[i][s] = tDec = tDec<<24 ^ tDec>>>8;
     }
   }
   
   // Compactify.  Considerable speedup on Firefox.
   for (i = 0; i < 5; i++) {
     encTable[i] = encTable[i].slice(0);
     decTable[i] = decTable[i].slice(0);
   }
  },
  
  /**
   * Encryption and decryption core.
   * @param {Array} input Four words to be encrypted or decrypted.
   * @param dir The direction, 0 for encrypt and 1 for decrypt.
   * @return {Array} The four encrypted or decrypted words.
   * @private
   */
  _crypt:function (input, dir) {
    if (input.length !== 4) {
      throw new sjcl.exception.invalid("invalid aes block size");
    }
    
    var key = this._key[dir],
        // state variables a,b,c,d are loaded with pre-whitened data
        a = input[0]           ^ key[0],
        b = input[dir ? 3 : 1] ^ key[1],
        c = input[2]           ^ key[2],
        d = input[dir ? 1 : 3] ^ key[3],
        a2, b2, c2,
        
        nInnerRounds = key.length/4 - 2,
        i,
        kIndex = 4,
        out = [0,0,0,0],
        table = this._tables[dir],
        
        // load up the tables
        t0    = table[0],
        t1    = table[1],
        t2    = table[2],
        t3    = table[3],
        sbox  = table[4];
 
    // Inner rounds.  Cribbed from OpenSSL.
    for (i = 0; i < nInnerRounds; i++) {
      a2 = t0[a>>>24] ^ t1[b>>16 & 255] ^ t2[c>>8 & 255] ^ t3[d & 255] ^ key[kIndex];
      b2 = t0[b>>>24] ^ t1[c>>16 & 255] ^ t2[d>>8 & 255] ^ t3[a & 255] ^ key[kIndex + 1];
      c2 = t0[c>>>24] ^ t1[d>>16 & 255] ^ t2[a>>8 & 255] ^ t3[b & 255] ^ key[kIndex + 2];
      d  = t0[d>>>24] ^ t1[a>>16 & 255] ^ t2[b>>8 & 255] ^ t3[c & 255] ^ key[kIndex + 3];
      kIndex += 4;
      a=a2; b=b2; c=c2;
    }
        
    // Last round.
    for (i = 0; i < 4; i++) {
      out[dir ? 3&-i : i] =
        sbox[a>>>24      ]<<24 ^ 
        sbox[b>>16  & 255]<<16 ^
        sbox[c>>8   & 255]<<8  ^
        sbox[d      & 255]     ^
        key[kIndex++];
      a2=a; a=b; b=c; c=d; d=a2;
    }
    
    return out;
  }
};

/** @fileOverview Arrays of bits, encoded as arrays of Numbers.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Arrays of bits, encoded as arrays of Numbers.
 *
 * @description
 * <p>
 * These objects are the currency accepted by SJCL's crypto functions.
 * </p>
 *
 * <p>
 * Most of our crypto primitives operate on arrays of 4-byte words internally,
 * but many of them can take arguments that are not a multiple of 4 bytes.
 * This library encodes arrays of bits (whose size need not be a multiple of 8
 * bits) as arrays of 32-bit words.  The bits are packed, big-endian, into an
 * array of words, 32 bits at a time.  Since the words are double-precision
 * floating point numbers, they fit some extra data.  We use this (in a private,
 * possibly-changing manner) to encode the number of bits actually  present
 * in the last word of the array.
 * </p>
 *
 * <p>
 * Because bitwise ops clear this out-of-band data, these arrays can be passed
 * to ciphers like AES which want arrays of words.
 * </p>
 */
sjcl.bitArray = {
  /**
   * Array slices in units of bits.
   * @param {bitArray a} The array to slice.
   * @param {Number} bstart The offset to the start of the slice, in bits.
   * @param {Number} bend The offset to the end of the slice, in bits.  If this is undefined,
   * slice until the end of the array.
   * @return {bitArray} The requested slice.
   */
  bitSlice: function (a, bstart, bend) {
    a = sjcl.bitArray._shiftRight(a.slice(bstart/32), 32 - (bstart & 31)).slice(1);
    return (bend === undefined) ? a : sjcl.bitArray.clamp(a, bend-bstart);
  },

  /**
   * Extract a number packed into a bit array.
   * @param {bitArray} a The array to slice.
   * @param {Number} bstart The offset to the start of the slice, in bits.
   * @param {Number} length The length of the number to extract.
   * @return {Number} The requested slice.
   */
  extract: function(a, bstart, blength) {
    // FIXME: this Math.floor is not necessary at all, but for some reason
    // seems to suppress a bug in the Chromium JIT.
    var x, sh = Math.floor((-bstart-blength) & 31);
    if ((bstart + blength - 1 ^ bstart) & -32) {
      // it crosses a boundary
      x = (a[bstart/32|0] << (32 - sh)) ^ (a[bstart/32+1|0] >>> sh);
    } else {
      // within a single word
      x = a[bstart/32|0] >>> sh;
    }
    return x & ((1<<blength) - 1);
  },

  /**
   * Concatenate two bit arrays.
   * @param {bitArray} a1 The first array.
   * @param {bitArray} a2 The second array.
   * @return {bitArray} The concatenation of a1 and a2.
   */
  concat: function (a1, a2) {
    if (a1.length === 0 || a2.length === 0) {
      return a1.concat(a2);
    }
    
    var out, i, last = a1[a1.length-1], shift = sjcl.bitArray.getPartial(last);
    if (shift === 32) {
      return a1.concat(a2);
    } else {
      return sjcl.bitArray._shiftRight(a2, shift, last|0, a1.slice(0,a1.length-1));
    }
  },

  /**
   * Find the length of an array of bits.
   * @param {bitArray} a The array.
   * @return {Number} The length of a, in bits.
   */
  bitLength: function (a) {
    var l = a.length, x;
    if (l === 0) { return 0; }
    x = a[l - 1];
    return (l-1) * 32 + sjcl.bitArray.getPartial(x);
  },

  /**
   * Truncate an array.
   * @param {bitArray} a The array.
   * @param {Number} len The length to truncate to, in bits.
   * @return {bitArray} A new array, truncated to len bits.
   */
  clamp: function (a, len) {
    if (a.length * 32 < len) { return a; }
    a = a.slice(0, Math.ceil(len / 32));
    var l = a.length;
    len = len & 31;
    if (l > 0 && len) {
      a[l-1] = sjcl.bitArray.partial(len, a[l-1] & 0x80000000 >> (len-1), 1);
    }
    return a;
  },

  /**
   * Make a partial word for a bit array.
   * @param {Number} len The number of bits in the word.
   * @param {Number} x The bits.
   * @param {Number} [0] _end Pass 1 if x has already been shifted to the high side.
   * @return {Number} The partial word.
   */
  partial: function (len, x, _end) {
    if (len === 32) { return x; }
    return (_end ? x|0 : x << (32-len)) + len * 0x10000000000;
  },

  /**
   * Get the number of bits used by a partial word.
   * @param {Number} x The partial word.
   * @return {Number} The number of bits used by the partial word.
   */
  getPartial: function (x) {
    return Math.round(x/0x10000000000) || 32;
  },

  /**
   * Compare two arrays for equality in a predictable amount of time.
   * @param {bitArray} a The first array.
   * @param {bitArray} b The second array.
   * @return {boolean} true if a == b; false otherwise.
   */
  equal: function (a, b) {
    if (sjcl.bitArray.bitLength(a) !== sjcl.bitArray.bitLength(b)) {
      return false;
    }
    var x = 0, i;
    for (i=0; i<a.length; i++) {
      x |= a[i]^b[i];
    }
    return (x === 0);
  },

  /** Shift an array right.
   * @param {bitArray} a The array to shift.
   * @param {Number} shift The number of bits to shift.
   * @param {Number} [carry=0] A byte to carry in
   * @param {bitArray} [out=[]] An array to prepend to the output.
   * @private
   */
  _shiftRight: function (a, shift, carry, out) {
    var i, last2=0, shift2;
    if (out === undefined) { out = []; }
    
    for (; shift >= 32; shift -= 32) {
      out.push(carry);
      carry = 0;
    }
    if (shift === 0) {
      return out.concat(a);
    }
    
    for (i=0; i<a.length; i++) {
      out.push(carry | a[i]>>>shift);
      carry = a[i] << (32-shift);
    }
    last2 = a.length ? a[a.length-1] : 0;
    shift2 = sjcl.bitArray.getPartial(last2);
    out.push(sjcl.bitArray.partial(shift+shift2 & 31, (shift + shift2 > 32) ? carry : out.pop(),1));
    return out;
  },
  
  /** xor a block of 4 words together.
   * @private
   */
  _xor4: function(x,y) {
    return [x[0]^y[0],x[1]^y[1],x[2]^y[2],x[3]^y[3]];
  }
};
/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
 
/** @namespace UTF-8 strings */
sjcl.codec.utf8String = {
  /** Convert from a bitArray to a UTF-8 string. */
  fromBits: function (arr) {
    var out = "", bl = sjcl.bitArray.bitLength(arr), i, tmp;
    for (i=0; i<bl/8; i++) {
      if ((i&3) === 0) {
        tmp = arr[i/4];
      }
      out += String.fromCharCode(tmp >>> 24);
      tmp <<= 8;
    }
    return decodeURIComponent(escape(out));
  },
  
  /** Convert from a UTF-8 string to a bitArray. */
  toBits: function (str) {
    str = unescape(encodeURIComponent(str));
    var out = [], i, tmp=0;
    for (i=0; i<str.length; i++) {
      tmp = tmp << 8 | str.charCodeAt(i);
      if ((i&3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i&3) {
      out.push(sjcl.bitArray.partial(8*(i&3), tmp));
    }
    return out;
  }
};
/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Base64 encoding/decoding */
sjcl.codec.base64 = {
  /** The base64 alphabet.
   * @private
   */
  _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  
  /** Convert from a bitArray to a base64 string. */
  fromBits: function (arr, _noEquals, _url) {
    var out = "", i, bits=0, c = sjcl.codec.base64._chars, ta=0, bl = sjcl.bitArray.bitLength(arr);
    if (_url) c = c.substr(0,62) + '-_';
    for (i=0; out.length * 6 < bl; ) {
      out += c.charAt((ta ^ arr[i]>>>bits) >>> 26);
      if (bits < 6) {
        ta = arr[i] << (6-bits);
        bits += 26;
        i++;
      } else {
        ta <<= 6;
        bits -= 6;
      }
    }
    while ((out.length & 3) && !_noEquals) { out += "="; }
    return out;
  },
  
  /** Convert from a base64 string to a bitArray */
  toBits: function(str, _url) {
    str = str.replace(/\s|=/g,'');
    var out = [], i, bits=0, c = sjcl.codec.base64._chars, ta=0, x;
    if (_url) c = c.substr(0,62) + '-_';
    for (i=0; i<str.length; i++) {
      x = c.indexOf(str.charAt(i));
      if (x < 0) {
        throw new sjcl.exception.invalid("this isn't base64!");
      }
      if (bits > 26) {
        bits -= 26;
        out.push(ta ^ x>>>bits);
        ta  = x << (32-bits);
      } else {
        bits += 6;
        ta ^= x << (32-bits);
      }
    }
    if (bits&56) {
      out.push(sjcl.bitArray.partial(bits&56, ta, 1));
    }
    return out;
  }
};

sjcl.codec.base64url = {
  fromBits: function (arr) { return sjcl.codec.base64.fromBits(arr,1,1); },
  toBits: function (str) { return sjcl.codec.base64.toBits(str,1); }
};
/** @fileOverview Javascript SHA-256 implementation.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * Special thanks to Aldo Cortesi for pointing out several bugs in
 * this code.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Context for a SHA-256 operation in progress.
 * @constructor
 * @class Secure Hash Algorithm, 256 bits.
 */
sjcl.hash.sha256 = function (hash) {
  if (!this._key[0]) { this._precompute(); }
  if (hash) {
    this._h = hash._h.slice(0);
    this._buffer = hash._buffer.slice(0);
    this._length = hash._length;
  } else {
    this.reset();
  }
};

/**
 * Hash a string or an array of words.
 * @static
 * @param {bitArray|String} data the data to hash.
 * @return {bitArray} The hash value, an array of 16 big-endian words.
 */
sjcl.hash.sha256.hash = function (data) {
  return (new sjcl.hash.sha256()).update(data).finalize();
};

sjcl.hash.sha256.prototype = {
  /**
   * The hash's block size, in bits.
   * @constant
   */
  blockSize: 512,
   
  /**
   * Reset the hash state.
   * @return this
   */
  reset:function () {
    this._h = this._init.slice(0);
    this._buffer = [];
    this._length = 0;
    return this;
  },
  
  /**
   * Input several words to the hash.
   * @param {bitArray|String} data the data to hash.
   * @return this
   */
  update: function (data) {
    if (typeof data === "string") {
      data = sjcl.codec.utf8String.toBits(data);
    }
    var i, b = this._buffer = sjcl.bitArray.concat(this._buffer, data),
        ol = this._length,
        nl = this._length = ol + sjcl.bitArray.bitLength(data);
    for (i = 512+ol & -512; i <= nl; i+= 512) {
      this._block(b.splice(0,16));
    }
    return this;
  },
  
  /**
   * Complete hashing and output the hash value.
   * @return {bitArray} The hash value, an array of 16 big-endian words.
   */
  finalize:function () {
    var i, b = this._buffer, h = this._h;

    // Round out and push the buffer
    b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1,1)]);
    
    // Round out the buffer to a multiple of 16 words, less the 2 length words.
    for (i = b.length + 2; i & 15; i++) {
      b.push(0);
    }
    
    // append the length
    b.push(Math.floor(this._length / 0x100000000));
    b.push(this._length | 0);

    while (b.length) {
      this._block(b.splice(0,16));
    }

    this.reset();
    return h;
  },

  /**
   * The SHA-256 initialization vector, to be precomputed.
   * @private
   */
  _init:[],
  /*
  _init:[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
  */
  
  /**
   * The SHA-256 hash key, to be precomputed.
   * @private
   */
  _key:[],
  /*
  _key:
    [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
  */


  /**
   * Function to precompute _init and _key.
   * @private
   */
  _precompute: function () {
    var i = 0, prime = 2, factor;

    function frac(x) { return (x-Math.floor(x)) * 0x100000000 | 0; }

    outer: for (; i<64; prime++) {
      for (factor=2; factor*factor <= prime; factor++) {
        if (prime % factor === 0) {
          // not a prime
          continue outer;
        }
      }
      
      if (i<8) {
        this._init[i] = frac(Math.pow(prime, 1/2));
      }
      this._key[i] = frac(Math.pow(prime, 1/3));
      i++;
    }
  },
  
  /**
   * Perform one cycle of SHA-256.
   * @param {bitArray} words one block of words.
   * @private
   */
  _block:function (words) {  
    var i, tmp, a, b,
      w = words.slice(0),
      h = this._h,
      k = this._key,
      h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3],
      h4 = h[4], h5 = h[5], h6 = h[6], h7 = h[7];

    /* Rationale for placement of |0 :
     * If a value can overflow is original 32 bits by a factor of more than a few
     * million (2^23 ish), there is a possibility that it might overflow the
     * 53-bit mantissa and lose precision.
     *
     * To avoid this, we clamp back to 32 bits by |'ing with 0 on any value that
     * propagates around the loop, and on the hash state h[].  I don't believe
     * that the clamps on h4 and on h0 are strictly necessary, but it's close
     * (for h4 anyway), and better safe than sorry.
     *
     * The clamps on h[] are necessary for the output to be correct even in the
     * common case and for short inputs.
     */
    for (i=0; i<64; i++) {
      // load up the input word for this round
      if (i<16) {
        tmp = w[i];
      } else {
        a   = w[(i+1 ) & 15];
        b   = w[(i+14) & 15];
        tmp = w[i&15] = ((a>>>7  ^ a>>>18 ^ a>>>3  ^ a<<25 ^ a<<14) + 
                         (b>>>17 ^ b>>>19 ^ b>>>10 ^ b<<15 ^ b<<13) +
                         w[i&15] + w[(i+9) & 15]) | 0;
      }
      
      tmp = (tmp + h7 + (h4>>>6 ^ h4>>>11 ^ h4>>>25 ^ h4<<26 ^ h4<<21 ^ h4<<7) +  (h6 ^ h4&(h5^h6)) + k[i]); // | 0;
      
      // shift register
      h7 = h6; h6 = h5; h5 = h4;
      h4 = h3 + tmp | 0;
      h3 = h2; h2 = h1; h1 = h0;

      h0 = (tmp +  ((h1&h2) ^ (h3&(h1^h2))) + (h1>>>2 ^ h1>>>13 ^ h1>>>22 ^ h1<<30 ^ h1<<19 ^ h1<<10)) | 0;
    }

    h[0] = h[0]+h0 | 0;
    h[1] = h[1]+h1 | 0;
    h[2] = h[2]+h2 | 0;
    h[3] = h[3]+h3 | 0;
    h[4] = h[4]+h4 | 0;
    h[5] = h[5]+h5 | 0;
    h[6] = h[6]+h6 | 0;
    h[7] = h[7]+h7 | 0;
  }
};

/** @fileOverview GCM mode implementation.
 *
 * @author Juho Vähä-Herttua
 */

/** @namespace Galois/Counter mode. */
sjcl.mode.gcm = {
  /** The name of the mode.
   * @constant
   */
  name: "gcm",
  
  /** Encrypt in GCM mode.
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {bitArray} plaintext The plaintext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.
   * @param {Number} [tlen=128] The desired tag length, in bits.
   * @return {bitArray} The encrypted data, an array of bytes.
   */
  encrypt: function (prf, plaintext, iv, adata, tlen) {
    var out, data = plaintext.slice(0), w=sjcl.bitArray;
    tlen = tlen || 128;
    adata = adata || [];

    // encrypt and tag
    out = sjcl.mode.gcm._ctrMode(true, prf, data, adata, iv, tlen);

    return w.concat(out.data, out.tag);
  },
  
  /** Decrypt in GCM mode.
   * @static
   * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
   * @param {bitArray} ciphertext The ciphertext data.
   * @param {bitArray} iv The initialization value.
   * @param {bitArray} [adata=[]] The authenticated data.
   * @param {Number} [tlen=128] The desired tag length, in bits.
   * @return {bitArray} The decrypted data.
   */
  decrypt: function (prf, ciphertext, iv, adata, tlen) {
    var out, data = ciphertext.slice(0), tag, w=sjcl.bitArray, l=w.bitLength(data);
    tlen = tlen || 128;
    adata = adata || [];

    // Slice tag out of data
    if (tlen <= l) {
      tag = w.bitSlice(data, l-tlen);
      data = w.bitSlice(data, 0, l-tlen);
    } else {
      tag = data;
      data = [];
    }

    // decrypt and tag
    out = sjcl.mode.gcm._ctrMode(false, prf, data, adata, iv, tlen);

    if (!w.equal(out.tag, tag)) {
      throw new sjcl.exception.corrupt("gcm: tag doesn't match");
    }
    return out.data;
  },

  /* Compute the galois multiplication of X and Y
   * @private
   */
  _galoisMultiply: function (x, y) {
    var i, j, xi, Zi, Vi, lsb_Vi, w=sjcl.bitArray, xor=w._xor4;

    Zi = [0,0,0,0];
    Vi = y.slice(0);

    // Block size is 128 bits, run 128 times to get Z_128
    for (i=0; i<128; i++) {
      xi = (x[Math.floor(i/32)] & (1 << (31-i%32))) !== 0;
      if (xi) {
        // Z_i+1 = Z_i ^ V_i
        Zi = xor(Zi, Vi);
      }

      // Store the value of LSB(V_i)
      lsb_Vi = (Vi[3] & 1) !== 0;

      // V_i+1 = V_i >> 1
      for (j=3; j>0; j--) {
        Vi[j] = (Vi[j] >>> 1) | ((Vi[j-1]&1) << 31);
      }
      Vi[0] = Vi[0] >>> 1;

      // If LSB(V_i) is 1, V_i+1 = (V_i >> 1) ^ R
      if (lsb_Vi) {
        Vi[0] = Vi[0] ^ (0xe1 << 24);
      }
    }
    return Zi;
  },

  _ghash: function(H, Y0, data) {
    var Yi, i, l = data.length;

    Yi = Y0.slice(0);
    for (i=0; i<l; i+=4) {
      Yi[0] ^= 0xffffffff&data[i];
      Yi[1] ^= 0xffffffff&data[i+1];
      Yi[2] ^= 0xffffffff&data[i+2];
      Yi[3] ^= 0xffffffff&data[i+3];
      Yi = sjcl.mode.gcm._galoisMultiply(Yi, H);
    }
    return Yi;
  },

  /** GCM CTR mode.
   * Encrypt or decrypt data and tag with the prf in GCM-style CTR mode.
   * @param {Boolean} encrypt True if encrypt, false if decrypt.
   * @param {Object} prf The PRF.
   * @param {bitArray} data The data to be encrypted or decrypted.
   * @param {bitArray} iv The initialization vector.
   * @param {bitArray} adata The associated data to be tagged.
   * @param {Number} tlen The length of the tag, in bits.
   */
  _ctrMode: function(encrypt, prf, data, adata, iv, tlen) {
    var H, J0, S0, enc, i, ctr, tag, last, l, bl, abl, ivbl, w=sjcl.bitArray, xor=w._xor4;

    // Calculate data lengths
    l = data.length;
    bl = w.bitLength(data);
    abl = w.bitLength(adata);
    ivbl = w.bitLength(iv);

    // Calculate the parameters
    H = prf.encrypt([0,0,0,0]);
    if (ivbl === 96) {
      J0 = iv.slice(0);
      J0 = w.concat(J0, [1]);
    } else {
      J0 = sjcl.mode.gcm._ghash(H, [0,0,0,0], iv);
      J0 = sjcl.mode.gcm._ghash(H, J0, [0,0,Math.floor(ivbl/0x100000000),ivbl&0xffffffff]);
    }
    S0 = sjcl.mode.gcm._ghash(H, [0,0,0,0], adata);

    // Initialize ctr and tag
    ctr = J0.slice(0);
    tag = S0.slice(0);

    // If decrypting, calculate hash
    if (!encrypt) {
      tag = sjcl.mode.gcm._ghash(H, S0, data);
    }

    // Encrypt all the data
    for (i=0; i<l; i+=4) {
       ctr[3]++;
       enc = prf.encrypt(ctr);
       data[i]   ^= enc[0];
       data[i+1] ^= enc[1];
       data[i+2] ^= enc[2];
       data[i+3] ^= enc[3];
    }
    data = w.clamp(data, bl);

    // If encrypting, calculate hash
    if (encrypt) {
      tag = sjcl.mode.gcm._ghash(H, S0, data);
    }

    // Calculate last block from bit lengths, ugly because bitwise operations are 32-bit
    last = [
      Math.floor(abl/0x100000000), abl&0xffffffff,
      Math.floor(bl/0x100000000), bl&0xffffffff
    ];

    // Calculate the final tag block
    tag = sjcl.mode.gcm._ghash(H, tag, last);
    enc = prf.encrypt(J0);
    tag[0] ^= enc[0];
    tag[1] ^= enc[1];
    tag[2] ^= enc[2];
    tag[3] ^= enc[3];

    return { tag:w.bitSlice(tag, 0, tlen), data:data };
  }
};

/** @fileOverview HMAC implementation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** HMAC with the specified hash function.
 * @constructor
 * @param {bitArray} key the key for HMAC.
 * @param {Object} [hash=sjcl.hash.sha256] The hash function to use.
 */
sjcl.misc.hmac = function (key, Hash) {
  this._hash = Hash = Hash || sjcl.hash.sha256;
  var exKey = [[],[]], i,
      bs = Hash.prototype.blockSize / 32;
  this._baseHash = [new Hash(), new Hash()];

  if (key.length > bs) {
    key = Hash.hash(key);
  }
  
  for (i=0; i<bs; i++) {
    exKey[0][i] = key[i]^0x36363636;
    exKey[1][i] = key[i]^0x5C5C5C5C;
  }
  
  this._baseHash[0].update(exKey[0]);
  this._baseHash[1].update(exKey[1]);
};

/** HMAC with the specified hash function.  Also called encrypt since it's a prf.
 * @param {bitArray|String} data The data to mac.
 * @param {Codec} [encoding] the encoding function to use.
 */
sjcl.misc.hmac.prototype.encrypt = sjcl.misc.hmac.prototype.mac = function (data, encoding) {
  var w = new (this._hash)(this._baseHash[0]).update(data, encoding).finalize();
  return new (this._hash)(this._baseHash[1]).update(w).finalize();
};

/** @fileOverview Password-based key-derivation function, version 2.0.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** Password-Based Key-Derivation Function, version 2.0.
 *
 * Generate keys from passwords using PBKDF2-HMAC-SHA256.
 *
 * This is the method specified by RSA's PKCS #5 standard.
 *
 * @param {bitArray|String} password  The password.
 * @param {bitArray} salt The salt.  Should have lots of entropy.
 * @param {Number} [count=1000] The number of iterations.  Higher numbers make the function slower but more secure.
 * @param {Number} [length] The length of the derived key.  Defaults to the
                            output size of the hash function.
 * @param {Object} [Prff=sjcl.misc.hmac] The pseudorandom function family.
 * @return {bitArray} the derived key.
 */
sjcl.misc.pbkdf2 = function (password, salt, count, length, Prff) {
  count = count || 1000;
  
  if (length < 0 || count < 0) {
    throw sjcl.exception.invalid("invalid params to pbkdf2");
  }
  
  if (typeof password === "string") {
    password = sjcl.codec.utf8String.toBits(password);
  }
  
  Prff = Prff || sjcl.misc.hmac;
  
  var prf = new Prff(password),
      u, ui, i, j, k, out = [], b = sjcl.bitArray;

  for (k = 1; 32 * out.length < (length || 1); k++) {
    u = ui = prf.encrypt(b.concat(salt,[k]));
    
    for (i=1; i<count; i++) {
      ui = prf.encrypt(ui);
      for (j=0; j<ui.length; j++) {
        u[j] ^= ui[j];
      }
    }
    
    out = out.concat(u);
  }

  if (length) { out = b.clamp(out, length); }

  return out;
};
/** @fileOverview Random number generator.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Random number generator
 *
 * @description
 * <p>
 * This random number generator is a derivative of Ferguson and Schneier's
 * generator Fortuna.  It collects entropy from various events into several
 * pools, implemented by streaming SHA-256 instances.  It differs from
 * ordinary Fortuna in a few ways, though.
 * </p>
 *
 * <p>
 * Most importantly, it has an entropy estimator.  This is present because
 * there is a strong conflict here between making the generator available
 * as soon as possible, and making sure that it doesn't "run on empty".
 * In Fortuna, there is a saved state file, and the system is likely to have
 * time to warm up.
 * </p>
 *
 * <p>
 * Second, because users are unlikely to stay on the page for very long,
 * and to speed startup time, the number of pools increases logarithmically:
 * a new pool is created when the previous one is actually used for a reseed.
 * This gives the same asymptotic guarantees as Fortuna, but gives more
 * entropy to early reseeds.
 * </p>
 *
 * <p>
 * The entire mechanism here feels pretty klunky.  Furthermore, there are
 * several improvements that should be made, including support for
 * dedicated cryptographic functions that may be present in some browsers;
 * state files in local storage; cookies containing randomness; etc.  So
 * look for improvements in future versions.
 * </p>
 */
sjcl.random = {
  /** Generate several random words, and return them in an array
   * @param {Number} nwords The number of words to generate.
   */
  randomWords: function (nwords, paranoia) {
    var out = [], i, readiness = this.isReady(paranoia), g;
  
    if (readiness === this._NOT_READY) {
      throw new sjcl.exception.notReady("generator isn't seeded");
    } else if (readiness & this._REQUIRES_RESEED) {
      this._reseedFromPools(!(readiness & this._READY));
    }
  
    for (i=0; i<nwords; i+= 4) {
      if ((i+1) % this._MAX_WORDS_PER_BURST === 0) {
        this._gate();
      }
   
      g = this._gen4words();
      out.push(g[0],g[1],g[2],g[3]);
    }
    this._gate();
  
    return out.slice(0,nwords);
  },
  
  setDefaultParanoia: function (paranoia) {
    this._defaultParanoia = paranoia;
  },
  
  /**
   * Add entropy to the pools.
   * @param data The entropic value.  Should be a 32-bit integer, array of 32-bit integers, or string
   * @param {Number} estimatedEntropy The estimated entropy of data, in bits
   * @param {String} source The source of the entropy, eg "mouse"
   */
  addEntropy: function (data, estimatedEntropy, source) {
    source = source || "user";
  
    var id,
      i, tmp,
      t = (new Date()).valueOf(),
      robin = this._robins[source],
      oldReady = this.isReady(), err = 0;
      
    id = this._collectorIds[source];
    if (id === undefined) { id = this._collectorIds[source] = this._collectorIdNext ++; }
      
    if (robin === undefined) { robin = this._robins[source] = 0; }
    this._robins[source] = ( this._robins[source] + 1 ) % this._pools.length;
  
    switch(typeof(data)) {
      
    case "number":
      if (estimatedEntropy === undefined) {
        estimatedEntropy = 1;
      }
      this._pools[robin].update([id,this._eventId++,1,estimatedEntropy,t,1,data|0]);
      break;
      
    case "object":
      var objName = Object.prototype.toString.call(data);
      if (objName === "[object Uint32Array]") {
        tmp = [];
        for (i = 0; i < data.length; i++) {
          tmp.push(data[i]);
        }
        data = tmp;
      } else {
        if (objName !== "[object Array]") {
          err = 1;
        }
        for (i=0; i<data.length && !err; i++) {
          if (typeof(data[i]) != "number") {
            err = 1;
          }
        }
      }
      if (!err) {
        if (estimatedEntropy === undefined) {
          /* horrible entropy estimator */
          estimatedEntropy = 0;
          for (i=0; i<data.length; i++) {
            tmp= data[i];
            while (tmp>0) {
              estimatedEntropy++;
              tmp = tmp >>> 1;
            }
          }
        }
        this._pools[robin].update([id,this._eventId++,2,estimatedEntropy,t,data.length].concat(data));
      }
      break;
      
    case "string":
      if (estimatedEntropy === undefined) {
       /* English text has just over 1 bit per character of entropy.
        * But this might be HTML or something, and have far less
        * entropy than English...  Oh well, let's just say one bit.
        */
       estimatedEntropy = data.length;
      }
      this._pools[robin].update([id,this._eventId++,3,estimatedEntropy,t,data.length]);
      this._pools[robin].update(data);
      break;
      
    default:
      err=1;
    }
    if (err) {
      throw new sjcl.exception.bug("random: addEntropy only supports number, array of numbers or string");
    }
  
    /* record the new strength */
    this._poolEntropy[robin] += estimatedEntropy;
    this._poolStrength += estimatedEntropy;
  
    /* fire off events */
    if (oldReady === this._NOT_READY) {
      if (this.isReady() !== this._NOT_READY) {
        this._fireEvent("seeded", Math.max(this._strength, this._poolStrength));
      }
      this._fireEvent("progress", this.getProgress());
    }
  },
  
  /** Is the generator ready? */
  isReady: function (paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[ (paranoia !== undefined) ? paranoia : this._defaultParanoia ];
  
    if (this._strength && this._strength >= entropyRequired) {
      return (this._poolEntropy[0] > this._BITS_PER_RESEED && (new Date()).valueOf() > this._nextReseed) ?
        this._REQUIRES_RESEED | this._READY :
        this._READY;
    } else {
      return (this._poolStrength >= entropyRequired) ?
        this._REQUIRES_RESEED | this._NOT_READY :
        this._NOT_READY;
    }
  },
  
  /** Get the generator's progress toward readiness, as a fraction */
  getProgress: function (paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[ paranoia ? paranoia : this._defaultParanoia ];
  
    if (this._strength >= entropyRequired) {
      return 1.0;
    } else {
      return (this._poolStrength > entropyRequired) ?
        1.0 :
        this._poolStrength / entropyRequired;
    }
  },
  
  /** start the built-in entropy collectors */
  startCollectors: function () {
    if (this._collectorsStarted) { return; }
  
    if (window.addEventListener) {
      window.addEventListener("load", this._loadTimeCollector, false);
      window.addEventListener("mousemove", this._mouseCollector, false);
    } else if (document.attachEvent) {
      document.attachEvent("onload", this._loadTimeCollector);
      document.attachEvent("onmousemove", this._mouseCollector);
    }
    else {
      throw new sjcl.exception.bug("can't attach event");
    }
  
    this._collectorsStarted = true;
  },
  
  /** stop the built-in entropy collectors */
  stopCollectors: function () {
    if (!this._collectorsStarted) { return; }
  
    if (window.removeEventListener) {
      window.removeEventListener("load", this._loadTimeCollector, false);
      window.removeEventListener("mousemove", this._mouseCollector, false);
    } else if (window.detachEvent) {
      window.detachEvent("onload", this._loadTimeCollector);
      window.detachEvent("onmousemove", this._mouseCollector);
    }
    this._collectorsStarted = false;
  },
  
  /* use a cookie to store entropy.
  useCookie: function (all_cookies) {
      throw new sjcl.exception.bug("random: useCookie is unimplemented");
  },*/
  
  /** add an event listener for progress or seeded-ness. */
  addEventListener: function (name, callback) {
    this._callbacks[name][this._callbackI++] = callback;
  },
  
  /** remove an event listener for progress or seeded-ness */
  removeEventListener: function (name, cb) {
    var i, j, cbs=this._callbacks[name], jsTemp=[];
  
    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */
  
    for (j in cbs) {
	if (cbs.hasOwnProperty(j) && cbs[j] === cb) {
        jsTemp.push(j);
      }
    }
  
    for (i=0; i<jsTemp.length; i++) {
      j = jsTemp[i];
      delete cbs[j];
    }
  },
  
  /* private */
  _pools                   : [new sjcl.hash.sha256()],
  _poolEntropy             : [0],
  _reseedCount             : 0,
  _robins                  : {},
  _eventId                 : 0,
  
  _collectorIds            : {},
  _collectorIdNext         : 0,
  
  _strength                : 0,
  _poolStrength            : 0,
  _nextReseed              : 0,
  _key                     : [0,0,0,0,0,0,0,0],
  _counter                 : [0,0,0,0],
  _cipher                  : undefined,
  _defaultParanoia         : 6,
  
  /* event listener stuff */
  _collectorsStarted       : false,
  _callbacks               : {progress: {}, seeded: {}},
  _callbackI               : 0,
  
  /* constants */
  _NOT_READY               : 0,
  _READY                   : 1,
  _REQUIRES_RESEED         : 2,

  _MAX_WORDS_PER_BURST     : 65536,
  _PARANOIA_LEVELS         : [0,48,64,96,128,192,256,384,512,768,1024],
  _MILLISECONDS_PER_RESEED : 30000,
  _BITS_PER_RESEED         : 80,
  
  /** Generate 4 random words, no reseed, no gate.
   * @private
   */
  _gen4words: function () {
    for (var i=0; i<4; i++) {
      this._counter[i] = this._counter[i]+1 | 0;
      if (this._counter[i]) { break; }
    }
    return this._cipher.encrypt(this._counter);
  },
  
  /* Rekey the AES instance with itself after a request, or every _MAX_WORDS_PER_BURST words.
   * @private
   */
  _gate: function () {
    this._key = this._gen4words().concat(this._gen4words());
    this._cipher = new sjcl.cipher.aes(this._key);
  },
  
  /** Reseed the generator with the given words
   * @private
   */
  _reseed: function (seedWords) {
    this._key = sjcl.hash.sha256.hash(this._key.concat(seedWords));
    this._cipher = new sjcl.cipher.aes(this._key);
    for (var i=0; i<4; i++) {
      this._counter[i] = this._counter[i]+1 | 0;
      if (this._counter[i]) { break; }
    }
  },
  
  /** reseed the data from the entropy pools
   * @param full If set, use all the entropy pools in the reseed.
   */
  _reseedFromPools: function (full) {
    var reseedData = [], strength = 0, i;
  
    this._nextReseed = reseedData[0] =
      (new Date()).valueOf() + this._MILLISECONDS_PER_RESEED;
    
    for (i=0; i<16; i++) {
      /* On some browsers, this is cryptographically random.  So we might
       * as well toss it in the pot and stir...
       */
      reseedData.push(Math.random()*0x100000000|0);
    }
    
    for (i=0; i<this._pools.length; i++) {
     reseedData = reseedData.concat(this._pools[i].finalize());
     strength += this._poolEntropy[i];
     this._poolEntropy[i] = 0;
   
     if (!full && (this._reseedCount & (1<<i))) { break; }
    }
  
    /* if we used the last pool, push a new one onto the stack */
    if (this._reseedCount >= 1 << this._pools.length) {
     this._pools.push(new sjcl.hash.sha256());
     this._poolEntropy.push(0);
    }
  
    /* how strong was this reseed? */
    this._poolStrength -= strength;
    if (strength > this._strength) {
      this._strength = strength;
    }
  
    this._reseedCount ++;
    this._reseed(reseedData);
  },
  
  _mouseCollector: function (ev) {
    var x = ev.x || ev.clientX || ev.offsetX, y = ev.y || ev.clientY || ev.offsetY;
    sjcl.random.addEntropy([x,y], 2, "mouse");
  },
  
  _loadTimeCollector: function (ev) {
    sjcl.random.addEntropy((new Date()).valueOf(), 2, "loadtime");
  },
  
  _fireEvent: function (name, arg) {
    var j, cbs=sjcl.random._callbacks[name], cbsTemp=[];
    /* TODO: there is a race condition between removing collectors and firing them */ 

    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */
  
    for (j in cbs) {
     if (cbs.hasOwnProperty(j)) {
        cbsTemp.push(cbs[j]);
     }
    }
  
    for (j=0; j<cbsTemp.length; j++) {
     cbsTemp[j](arg);
    }
  }
};

(function(){
  try {
    // get cryptographically strong entropy in Webkit
    var ab = new Uint32Array(32);
    crypto.getRandomValues(ab);
    sjcl.random.addEntropy(ab, 1024, "crypto.getRandomValues");
  } catch (e) {
    // no getRandomValues :-(
  }
})();
/** @fileOverview Convenince functions centered around JSON encapsulation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
 
 /** @namespace JSON encapsulation */
 sjcl.json = {
  /** Default values for encryption */
  defaults: { v:1, iter:1000, ks:128, ts:64, mode:"ccm", adata:"", cipher:"aes" },

  /** Simple encryption function.
   * @param {String|bitArray} password The password or key.
   * @param {String} plaintext The data to encrypt.
   * @param {Object} [params] The parameters including tag, iv and salt.
   * @param {Object} [rp] A returned version with filled-in parameters.
   * @return {String} The ciphertext.
   * @throws {sjcl.exception.invalid} if a parameter is invalid.
   */
  encrypt: function (password, plaintext, params, rp) {
    params = params || {};
    rp = rp || {};
    
    var j = sjcl.json, p = j._add({ iv: sjcl.random.randomWords(4,0) },
                                  j.defaults), tmp, prp, adata;
    j._add(p, params);
    adata = p.adata;
    if (typeof p.salt === "string") {
      p.salt = sjcl.codec.base64.toBits(p.salt);
    }
    if (typeof p.iv === "string") {
      p.iv = sjcl.codec.base64.toBits(p.iv);
    }
    
    if (!sjcl.mode[p.mode] ||
        !sjcl.cipher[p.cipher] ||
        (typeof password === "string" && p.iter <= 100) ||
        (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
        (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
        (p.iv.length < 2 || p.iv.length > 4)) {
      throw new sjcl.exception.invalid("json encrypt: invalid parameters");
    }
    
    if (typeof password === "string") {
      tmp = sjcl.misc.cachedPbkdf2(password, p);
      password = tmp.key.slice(0,p.ks/32);
      p.salt = tmp.salt;
    } else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.publicKey) {
      tmp = password.kem();
      p.kemtag = tmp.tag;
      password = tmp.key.slice(0,p.ks/32);
    }
    if (typeof plaintext === "string") {
      plaintext = sjcl.codec.utf8String.toBits(plaintext);
    }
    if (typeof adata === "string") {
      adata = sjcl.codec.utf8String.toBits(adata);
    }
    prp = new sjcl.cipher[p.cipher](password);
    
    /* return the json data */
    j._add(rp, p);
    rp.key = password;
    
    /* do the encryption */
    p.ct = sjcl.mode[p.mode].encrypt(prp, plaintext, p.iv, adata, p.ts);
    
    //return j.encode(j._subtract(p, j.defaults));
    return j.encode(p);
  },
  
  /** Simple decryption function.
   * @param {String|bitArray} password The password or key.
   * @param {String} ciphertext The ciphertext to decrypt.
   * @param {Object} [params] Additional non-default parameters.
   * @param {Object} [rp] A returned object with filled parameters.
   * @return {String} The plaintext.
   * @throws {sjcl.exception.invalid} if a parameter is invalid.
   * @throws {sjcl.exception.corrupt} if the ciphertext is corrupt.
   */
  decrypt: function (password, ciphertext, params, rp) {
    params = params || {};
    rp = rp || {};
    
    var j = sjcl.json, p = j._add(j._add(j._add({},j.defaults),j.decode(ciphertext)), params, true), ct, tmp, prp, adata=p.adata;
    if (typeof p.salt === "string") {
      p.salt = sjcl.codec.base64.toBits(p.salt);
    }
    if (typeof p.iv === "string") {
      p.iv = sjcl.codec.base64.toBits(p.iv);
    }
    
    if (!sjcl.mode[p.mode] ||
        !sjcl.cipher[p.cipher] ||
        (typeof password === "string" && p.iter <= 100) ||
        (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
        (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
        (!p.iv) ||
        (p.iv.length < 2 || p.iv.length > 4)) {
      throw new sjcl.exception.invalid("json decrypt: invalid parameters");
    }
    
    if (typeof password === "string") {
      tmp = sjcl.misc.cachedPbkdf2(password, p);
      password = tmp.key.slice(0,p.ks/32);
      p.salt  = tmp.salt;
    } else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.secretKey) {
      password = password.unkem(sjcl.codec.base64.toBits(p.kemtag)).slice(0,p.ks/32);
    }
    if (typeof adata === "string") {
      adata = sjcl.codec.utf8String.toBits(adata);
    }
    prp = new sjcl.cipher[p.cipher](password);
    
    /* do the decryption */
    ct = sjcl.mode[p.mode].decrypt(prp, p.ct, p.iv, adata, p.ts);
    
    /* return the json data */
    j._add(rp, p);
    rp.key = password;
    
    return sjcl.codec.utf8String.fromBits(ct);
  },
  
  /** Encode a flat structure into a JSON string.
   * @param {Object} obj The structure to encode.
   * @return {String} A JSON string.
   * @throws {sjcl.exception.invalid} if obj has a non-alphanumeric property.
   * @throws {sjcl.exception.bug} if a parameter has an unsupported type.
   */
  encode: function (obj) {
    var i, out='{', comma='';
    for (i in obj) {
      if (obj.hasOwnProperty(i)) {
        if (!i.match(/^[a-z0-9]+$/i)) {
          throw new sjcl.exception.invalid("json encode: invalid property name");
        }
        out += comma + '"' + i + '":';
        comma = ',';
        
        switch (typeof obj[i]) {
        case 'number':
        case 'boolean':
          out += obj[i];
          break;
          
        case 'string':
          out += '"' + escape(obj[i]) + '"';
          break;
        
        case 'object':
          out += '"' + sjcl.codec.base64.fromBits(obj[i],1) + '"';
          break;
        
        default:
          throw new sjcl.exception.bug("json encode: unsupported type");
        }
      }
    }
    return out+'}';
  },
  
  /** Decode a simple (flat) JSON string into a structure.  The ciphertext,
   * adata, salt and iv will be base64-decoded.
   * @param {String} str The string.
   * @return {Object} The decoded structure.
   * @throws {sjcl.exception.invalid} if str isn't (simple) JSON.
   */
  decode: function (str) {
    str = str.replace(/\s/g,'');
    if (!str.match(/^\{.*\}$/)) { 
      throw new sjcl.exception.invalid("json decode: this isn't json!");
    }
    var a = str.replace(/^\{|\}$/g, '').split(/,/), out={}, i, m;
    for (i=0; i<a.length; i++) {
      if (!(m=a[i].match(/^(?:(["']?)([a-z][a-z0-9]*)\1):(?:(\d+)|"([a-z0-9+\/%*_.@=\-]*)")$/i))) {
        throw new sjcl.exception.invalid("json decode: this isn't json!");
      }
      if (m[3]) {
        out[m[2]] = parseInt(m[3],10);
      } else {
        out[m[2]] = m[2].match(/^(ct|salt|iv)$/) ? sjcl.codec.base64.toBits(m[4]) : unescape(m[4]);
      }
    }
    return out;
  },

  /** Insert all elements of src into target, modifying and returning target.
   * @param {Object} target The object to be modified.
   * @param {Object} src The object to pull data from.
   * @param {boolean} [requireSame=false] If true, throw an exception if any field of target differs from corresponding field of src.
   * @return {Object} target.
   * @private
   */
  _add: function (target, src, requireSame) {
    if (target === undefined) { target = {}; }
    if (src === undefined) { return target; }
    var i;
    for (i in src) {
      if (src.hasOwnProperty(i)) {
        if (requireSame && target[i] !== undefined && target[i] !== src[i]) {
          throw new sjcl.exception.invalid("required parameter overridden");
        }
        target[i] = src[i];
      }
    }
    return target;
  },
  
  /** Remove all elements of minus from plus.  Does not modify plus.
   * @private
   */
  _subtract: function (plus, minus) {
    var out = {}, i;
    
    for (i in plus) {
      if (plus.hasOwnProperty(i) && plus[i] !== minus[i]) {
        out[i] = plus[i];
      }
    }
    
    return out;
  },
  
  /** Return only the specified elements of src.
   * @private
   */
  _filter: function (src, filter) {
    var out = {}, i;
    for (i=0; i<filter.length; i++) {
      if (src[filter[i]] !== undefined) {
        out[filter[i]] = src[filter[i]];
      }
    }
    return out;
  }
};

/** Simple encryption function; convenient shorthand for sjcl.json.encrypt.
 * @param {String|bitArray} password The password or key.
 * @param {String} plaintext The data to encrypt.
 * @param {Object} [params] The parameters including tag, iv and salt.
 * @param {Object} [rp] A returned version with filled-in parameters.
 * @return {String} The ciphertext.
 */
sjcl.encrypt = sjcl.json.encrypt;

/** Simple decryption function; convenient shorthand for sjcl.json.decrypt.
 * @param {String|bitArray} password The password or key.
 * @param {String} ciphertext The ciphertext to decrypt.
 * @param {Object} [params] Additional non-default parameters.
 * @param {Object} [rp] A returned object with filled parameters.
 * @return {String} The plaintext.
 */
sjcl.decrypt = sjcl.json.decrypt;

/** The cache for cachedPbkdf2.
 * @private
 */
sjcl.misc._pbkdf2Cache = {};

/** Cached PBKDF2 key derivation.
 * @param {String} The password.  
 * @param {Object} The derivation params (iteration count and optional salt).
 * @return {Object} The derived data in key, the salt in salt.
 */
sjcl.misc.cachedPbkdf2 = function (password, obj) {
  var cache = sjcl.misc._pbkdf2Cache, c, cp, str, salt, iter;
  
  obj = obj || {};
  iter = obj.iter || 1000;
  
  /* open the cache for this password and iteration count */
  cp = cache[password] = cache[password] || {};
  c = cp[iter] = cp[iter] || { firstSalt: (obj.salt && obj.salt.length) ?
                     obj.salt.slice(0) : sjcl.random.randomWords(2,0) };
          
  salt = (obj.salt === undefined) ? c.firstSalt : obj.salt;
  
  c[salt] = c[salt] || sjcl.misc.pbkdf2(password, salt, obj.iter);
  return { key: c[salt].slice(0), salt:salt.slice(0) };
};


/**
 * Constructs a new bignum from another bignum, a number or a hex string.
 */
sjcl.bn = function(it) {
  this.initWith(it);
};

sjcl.bn.prototype = {
  radix: 24,
  maxMul: 8,
  _class: sjcl.bn,
  
  copy: function() {
    return new this._class(this);
  },

  /**
   * Initializes this with it, either as a bn, a number, or a hex string.
   */
  initWith: function(it) {
    var i=0, k, n, l;
    switch(typeof it) {
    case "object":
      this.limbs = it.limbs.slice(0);
      break;
      
    case "number":
      this.limbs = [it];
      this.normalize();
      break;
      
    case "string":
      it = it.replace(/^0x/, '');
      this.limbs = [];
      // hack
      k = this.radix / 4;
      for (i=0; i < it.length; i+=k) {
        this.limbs.push(parseInt(it.substring(Math.max(it.length - i - k, 0), it.length - i),16));
      }
      break;

    default:
      this.limbs = [0];
    }
    return this;
  },

  /**
   * Returns true if "this" and "that" are equal.  Calls fullReduce().
   * Equality test is in constant time.
   */
  equals: function(that) {
    if (typeof that === "number") { that = new this._class(that); }
    var difference = 0, i;
    this.fullReduce();
    that.fullReduce();
    for (i = 0; i < this.limbs.length || i < that.limbs.length; i++) {
      difference |= this.getLimb(i) ^ that.getLimb(i);
    }
    return (difference === 0);
  },
  
  /**
   * Get the i'th limb of this, zero if i is too large.
   */
  getLimb: function(i) {
    return (i >= this.limbs.length) ? 0 : this.limbs[i];
  },
  
  /**
   * Constant time comparison function.
   * Returns 1 if this >= that, or zero otherwise.
   */
  greaterEquals: function(that) {
    if (typeof that === "number") { that = new this._class(that); }
    var less = 0, greater = 0, i, a, b;
    i = Math.max(this.limbs.length, that.limbs.length) - 1;
    for (; i>= 0; i--) {
      a = this.getLimb(i);
      b = that.getLimb(i);
      greater |= (b - a) & ~less;
      less |= (a - b) & ~greater;
    }
    return (greater | ~less) >>> 31;
  },
  
  /**
   * Convert to a hex string.
   */
  toString: function() {
    this.fullReduce();
    var out="", i, s, l = this.limbs;
    for (i=0; i < this.limbs.length; i++) {
      s = l[i].toString(16);
      while (i < this.limbs.length - 1 && s.length < 6) {
        s = "0" + s;
      }
      out = s + out;
    }
    return "0x"+out;
  },
  
  /** this += that.  Does not normalize. */
  addM: function(that) {
    if (typeof(that) !== "object") { that = new this._class(that); }
    var i, l=this.limbs, ll=that.limbs;
    for (i=l.length; i<ll.length; i++) {
      l[i] = 0;
    }
    for (i=0; i<ll.length; i++) {
      l[i] += ll[i];
    }
    return this;
  },
  
  /** this *= 2.  Requires normalized; ends up normalized. */
  doubleM: function() {
    var i, carry=0, tmp, r=this.radix, m=this.radixMask, l=this.limbs;
    for (i=0; i<l.length; i++) {
      tmp = l[i];
      tmp = tmp+tmp+carry;
      l[i] = tmp & m;
      carry = tmp >> r;
    }
    if (carry) {
      l.push(carry);
    }
    return this;
  },
  
  /** this /= 2, rounded down.  Requires normalized; ends up normalized. */
  halveM: function() {
    var i, carry=0, tmp, r=this.radix, l=this.limbs;
    for (i=l.length-1; i>=0; i--) {
      tmp = l[i];
      l[i] = (tmp+carry)>>1;
      carry = (tmp&1) << r;
    }
    if (!l[l.length-1]) {
      l.pop();
    }
    return this;
  },

  /** this -= that.  Does not normalize. */
  subM: function(that) {
    if (typeof(that) !== "object") { that = new this._class(that); }
    var i, l=this.limbs, ll=that.limbs;
    for (i=l.length; i<ll.length; i++) {
      l[i] = 0;
    }
    for (i=0; i<ll.length; i++) {
      l[i] -= ll[i];
    }
    return this;
  },
  
  mod: function(that) {
    that = new sjcl.bn(that).normalize(); // copy before we begin
    var out = new sjcl.bn(this).normalize(), ci=0;
    
    for (; out.greaterEquals(that); ci++) {
      that.doubleM();
    }
    for (; ci > 0; ci--) {
      that.halveM();
      if (out.greaterEquals(that)) {
        out.subM(that).normalize();
      }
    }
    return out.trim();
  },
  
  /** return inverse mod prime p.  p must be odd. Binary extended Euclidean algorithm mod p. */
  inverseMod: function(p) {
    var a = new sjcl.bn(1), b = new sjcl.bn(0), x = new sjcl.bn(this), y = new sjcl.bn(p), tmp, i, nz=1;
    
    if (!(p.limbs[0] & 1)) {
      throw (new sjcl.exception.invalid("inverseMod: p must be odd"));
    }
    
    // invariant: y is odd
    do {
      if (x.limbs[0] & 1) {
        if (!x.greaterEquals(y)) {
          // x < y; swap everything
          tmp = x; x = y; y = tmp;
          tmp = a; a = b; b = tmp;
        }
        x.subM(y);
        x.normalize();
        
        if (!a.greaterEquals(b)) {
          a.addM(p);
        }
        a.subM(b);
      }
      
      // cut everything in half
      x.halveM();
      if (a.limbs[0] & 1) {
        a.addM(p);
      }
      a.normalize();
      a.halveM();
      
      // check for termination: x ?= 0
      for (i=nz=0; i<x.limbs.length; i++) {
        nz |= x.limbs[i];
      }
    } while(nz);
    
    if (!y.equals(1)) {
      throw (new sjcl.exception.invalid("inverseMod: p and x must be relatively prime"));
    }
    
    return b;
  },
  
  /** this + that.  Does not normalize. */
  add: function(that) {
    return this.copy().addM(that);
  },

  /** this - that.  Does not normalize. */
  sub: function(that) {
    return this.copy().subM(that);
  },
  
  /** this * that.  Normalizes and reduces. */
  mul: function(that) {
    if (typeof(that) === "number") { that = new this._class(that); }
    var i, j, a = this.limbs, b = that.limbs, al = a.length, bl = b.length, out = new this._class(), c = out.limbs, ai, ii=this.maxMul;

    for (i=0; i < this.limbs.length + that.limbs.length + 1; i++) {
      c[i] = 0;
    }
    for (i=0; i<al; i++) {
      ai = a[i];
      for (j=0; j<bl; j++) {
        c[i+j] += ai * b[j];
      }
     
      if (!--ii) {
        ii = this.maxMul;
        out.cnormalize();
      }
    }
    return out.cnormalize().reduce();
  },

  /** this ^ 2.  Normalizes and reduces. */
  square: function() {
    return this.mul(this);
  },

  /** this ^ n.  Uses square-and-multiply.  Normalizes and reduces. */
  power: function(l) {
    if (typeof(l) === "number") {
      l = [l];
    } else if (l.limbs !== undefined) {
      l = l.normalize().limbs;
    }
    var i, j, out = new this._class(1), pow = this;

    for (i=0; i<l.length; i++) {
      for (j=0; j<this.radix; j++) {
        if (l[i] & (1<<j)) {
          out = out.mul(pow);
        }
        pow = pow.square();
      }
    }
    
    return out;
  },

  /** this * that mod N */
  mulmod: function(that, N) {
    return this.mod(N).mul(that.mod(N)).mod(N);
  },

  /** this ^ x mod N */
  powermod: function(x, N) {
    var result = new sjcl.bn(1), a = new sjcl.bn(this), k = new sjcl.bn(x);
    while (true) {
      if (k.limbs[0] & 1) { result = result.mulmod(a, N); }
      k.halveM();
      if (k.equals(0)) { break; }
      a = a.mulmod(a, N);
    }
    return result.normalize().reduce();
  },

  trim: function() {
    var l = this.limbs, p;
    do {
      p = l.pop();
    } while (l.length && p === 0);
    l.push(p);
    return this;
  },
  
  /** Reduce mod a modulus.  Stubbed for subclassing. */
  reduce: function() {
    return this;
  },

  /** Reduce and normalize. */
  fullReduce: function() {
    return this.normalize();
  },
  
  /** Propagate carries. */
  normalize: function() {
    var carry=0, i, pv = this.placeVal, ipv = this.ipv, l, m, limbs = this.limbs, ll = limbs.length, mask = this.radixMask;
    for (i=0; i < ll || (carry !== 0 && carry !== -1); i++) {
      l = (limbs[i]||0) + carry;
      m = limbs[i] = l & mask;
      carry = (l-m)*ipv;
    }
    if (carry === -1) {
      limbs[i-1] -= this.placeVal;
    }
    return this;
  },

  /** Constant-time normalize. Does not allocate additional space. */
  cnormalize: function() {
    var carry=0, i, ipv = this.ipv, l, m, limbs = this.limbs, ll = limbs.length, mask = this.radixMask;
    for (i=0; i < ll-1; i++) {
      l = limbs[i] + carry;
      m = limbs[i] = l & mask;
      carry = (l-m)*ipv;
    }
    limbs[i] += carry;
    return this;
  },
  
  /** Serialize to a bit array */
  toBits: function(len) {
    this.fullReduce();
    len = len || this.exponent || this.limbs.length * this.radix;
    var i = Math.floor((len-1)/24), w=sjcl.bitArray, e = (len + 7 & -8) % this.radix || this.radix,
        out = [w.partial(e, this.getLimb(i))];
    for (i--; i >= 0; i--) {
      out = w.concat(out, [w.partial(this.radix, this.getLimb(i))]);
    }
    return out;
  },
  
  /** Return the length in bits, rounded up to the nearest byte. */
  bitLength: function() {
    this.fullReduce();
    var out = this.radix * (this.limbs.length - 1),
        b = this.limbs[this.limbs.length - 1];
    for (; b; b >>= 1) {
      out ++;
    }
    return out+7 & -8;
  }
};

sjcl.bn.fromBits = function(bits) {
  var Class = this, out = new Class(), words=[], w=sjcl.bitArray, t = this.prototype,
      l = Math.min(this.bitLength || 0x100000000, w.bitLength(bits)), e = l % t.radix || t.radix;
  
  words[0] = w.extract(bits, 0, e);
  for (; e < l; e += t.radix) {
    words.unshift(w.extract(bits, e, t.radix));
  }

  out.limbs = words;
  return out;
};



sjcl.bn.prototype.ipv = 1 / (sjcl.bn.prototype.placeVal = Math.pow(2,sjcl.bn.prototype.radix));
sjcl.bn.prototype.radixMask = (1 << sjcl.bn.prototype.radix) - 1;

/**
 * Creates a new subclass of bn, based on reduction modulo a pseudo-Mersenne prime,
 * i.e. a prime of the form 2^e + sum(a * 2^b),where the sum is negative and sparse.
 */
sjcl.bn.pseudoMersennePrime = function(exponent, coeff) {
  function p(it) {
    this.initWith(it);
    /*if (this.limbs[this.modOffset]) {
      this.reduce();
    }*/
  }

  var ppr = p.prototype = new sjcl.bn(), i, tmp, mo;
  mo = ppr.modOffset = Math.ceil(tmp = exponent / ppr.radix);
  ppr.exponent = exponent;
  ppr.offset = [];
  ppr.factor = [];
  ppr.minOffset = mo;
  ppr.fullMask = 0;
  ppr.fullOffset = [];
  ppr.fullFactor = [];
  ppr.modulus = p.modulus = new sjcl.bn(Math.pow(2,exponent));
  
  ppr.fullMask = 0|-Math.pow(2, exponent % ppr.radix);

  for (i=0; i<coeff.length; i++) {
    ppr.offset[i] = Math.floor(coeff[i][0] / ppr.radix - tmp);
    ppr.fullOffset[i] = Math.ceil(coeff[i][0] / ppr.radix - tmp);
    ppr.factor[i] = coeff[i][1] * Math.pow(1/2, exponent - coeff[i][0] + ppr.offset[i] * ppr.radix);
    ppr.fullFactor[i] = coeff[i][1] * Math.pow(1/2, exponent - coeff[i][0] + ppr.fullOffset[i] * ppr.radix);
    ppr.modulus.addM(new sjcl.bn(Math.pow(2,coeff[i][0])*coeff[i][1]));
    ppr.minOffset = Math.min(ppr.minOffset, -ppr.offset[i]); // conservative
  }
  ppr._class = p;
  ppr.modulus.cnormalize();

  /** Approximate reduction mod p.  May leave a number which is negative or slightly larger than p. */
  ppr.reduce = function() {
    var i, k, l, mo = this.modOffset, limbs = this.limbs, aff, off = this.offset, ol = this.offset.length, fac = this.factor, ll;

    i = this.minOffset;
    while (limbs.length > mo) {
      l = limbs.pop();
      ll = limbs.length;
      for (k=0; k<ol; k++) {
        limbs[ll+off[k]] -= fac[k] * l;
      }
      
      i--;
      if (!i) {
        limbs.push(0);
        this.cnormalize();
        i = this.minOffset;
      }
    }
    this.cnormalize();

    return this;
  };
  
  ppr._strongReduce = (ppr.fullMask === -1) ? ppr.reduce : function() {
    var limbs = this.limbs, i = limbs.length - 1, k, l;
    this.reduce();
    if (i === this.modOffset - 1) {
      l = limbs[i] & this.fullMask;
      limbs[i] -= l;
      for (k=0; k<this.fullOffset.length; k++) {
        limbs[i+this.fullOffset[k]] -= this.fullFactor[k] * l;
      }
      this.normalize();
    }
  };

  /** mostly constant-time, very expensive full reduction. */
  ppr.fullReduce = function() {
    var greater, i;
    // massively above the modulus, may be negative
    
    this._strongReduce();
    // less than twice the modulus, may be negative

    this.addM(this.modulus);
    this.addM(this.modulus);
    this.normalize();
    // probably 2-3x the modulus
    
    this._strongReduce();
    // less than the power of 2.  still may be more than
    // the modulus

    // HACK: pad out to this length
    for (i=this.limbs.length; i<this.modOffset; i++) {
      this.limbs[i] = 0;
    }
    
    // constant-time subtract modulus
    greater = this.greaterEquals(this.modulus);
    for (i=0; i<this.limbs.length; i++) {
      this.limbs[i] -= this.modulus.limbs[i] * greater;
    }
    this.cnormalize();

    return this;
  };

  ppr.inverse = function() {
    return (this.power(this.modulus.sub(2)));
  };

  p.fromBits = sjcl.bn.fromBits;

  return p;
};

// a small Mersenne prime
sjcl.bn.prime = {
  p127: sjcl.bn.pseudoMersennePrime(127, [[0,-1]]),

  // Bernstein's prime for Curve25519
  p25519: sjcl.bn.pseudoMersennePrime(255, [[0,-19]]),

  // NIST primes
  p192: sjcl.bn.pseudoMersennePrime(192, [[0,-1],[64,-1]]),
  p224: sjcl.bn.pseudoMersennePrime(224, [[0,1],[96,-1]]),
  p256: sjcl.bn.pseudoMersennePrime(256, [[0,-1],[96,1],[192,1],[224,-1]]),
  p384: sjcl.bn.pseudoMersennePrime(384, [[0,-1],[32,1],[96,-1],[128,-1]]),
  p521: sjcl.bn.pseudoMersennePrime(521, [[0,-1]])
};

sjcl.bn.random = function(modulus, paranoia) {
  if (typeof modulus !== "object") { modulus = new sjcl.bn(modulus); }
  var words, i, l = modulus.limbs.length, m = modulus.limbs[l-1]+1, out = new sjcl.bn();
  while (true) {
    // get a sequence whose first digits make sense
    do {
      words = sjcl.random.randomWords(l, paranoia);
      if (words[l-1] < 0) { words[l-1] += 0x100000000; }
    } while (Math.floor(words[l-1] / m) === Math.floor(0x100000000 / m));
    words[l-1] %= m;

    // mask off all the limbs
    for (i=0; i<l-1; i++) {
      words[i] &= modulus.radixMask;
    }

    // check the rest of the digitssj
    out.limbs = words;
    if (!out.greaterEquals(modulus)) {
      return out;
    }
  }
};

sjcl.ecc = {};

/**
 * Represents a point on a curve in affine coordinates.
 * @constructor
 * @param {sjcl.ecc.curve} curve The curve that this point lies on.
 * @param {bigInt} x The x coordinate.
 * @param {bigInt} y The y coordinate.
 */
sjcl.ecc.point = function(curve,x,y) {
  if (x === undefined) {
    this.isIdentity = true;
  } else {
    this.x = x;
    this.y = y;
    this.isIdentity = false;
  }
  this.curve = curve;
};



sjcl.ecc.point.prototype = {
  toJac: function() {
    return new sjcl.ecc.pointJac(this.curve, this.x, this.y, new this.curve.field(1));
  },

  mult: function(k) {
    return this.toJac().mult(k, this).toAffine();
  },
  
  /**
   * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
   * @param {bigInt} k The coefficient to multiply this by.
   * @param {bigInt} k2 The coefficient to multiply affine2 this by.
   * @param {sjcl.ecc.point} affine The other point in affine coordinates.
   * @return {sjcl.ecc.pointJac} The result of the multiplication and addition, in Jacobian coordinates.
   */
  mult2: function(k, k2, affine2) {
    return this.toJac().mult2(k, this, k2, affine2).toAffine();
  },
  
  multiples: function() {
    var m, i, j;
    if (this._multiples === undefined) {
      j = this.toJac().doubl();
      m = this._multiples = [new sjcl.ecc.point(this.curve), this, j.toAffine()];
      for (i=3; i<16; i++) {
        j = j.add(this);
        m.push(j.toAffine());
      }
    }
    return this._multiples;
  },

  isValid: function() {
    return this.y.square().equals(this.curve.b.add(this.x.mul(this.curve.a.add(this.x.square()))));
  },

  toBits: function() {
    return sjcl.bitArray.concat(this.x.toBits(), this.y.toBits());
  }
};

/**
 * Represents a point on a curve in Jacobian coordinates. Coordinates can be specified as bigInts or strings (which
 * will be converted to bigInts).
 *
 * @constructor
 * @param {bigInt/string} x The x coordinate.
 * @param {bigInt/string} y The y coordinate.
 * @param {bigInt/string} z The z coordinate.
 * @param {sjcl.ecc.curve} curve The curve that this point lies on.
 */
sjcl.ecc.pointJac = function(curve, x, y, z) {
  if (x === undefined) {
    this.isIdentity = true;
  } else {
    this.x = x;
    this.y = y;
    this.z = z;
    this.isIdentity = false;
  }
  this.curve = curve;
};

sjcl.ecc.pointJac.prototype = {
  /**
   * Adds S and T and returns the result in Jacobian coordinates. Note that S must be in Jacobian coordinates and T must be in affine coordinates.
   * @param {sjcl.ecc.pointJac} S One of the points to add, in Jacobian coordinates.
   * @param {sjcl.ecc.point} T The other point to add, in affine coordinates.
   * @return {sjcl.ecc.pointJac} The sum of the two points, in Jacobian coordinates. 
   */
  add: function(T) {
    var S = this, sz2, c, d, c2, x1, x2, x, y1, y2, y, z;
    if (S.curve !== T.curve) {
      throw("sjcl.ecc.add(): Points must be on the same curve to add them!");
    }

    if (S.isIdentity) {
      return T.toJac();
    } else if (T.isIdentity) {
      return S;
    }

    sz2 = S.z.square();
    c = T.x.mul(sz2).subM(S.x);

    if (c.equals(0)) {
      if (S.y.equals(T.y.mul(sz2.mul(S.z)))) {
        // same point
        return S.doubl();
      } else {
        // inverses
        return new sjcl.ecc.pointJac(S.curve);
      }
    }
    
    d = T.y.mul(sz2.mul(S.z)).subM(S.y);
    c2 = c.square();

    x1 = d.square();
    x2 = c.square().mul(c).addM( S.x.add(S.x).mul(c2) );
    x  = x1.subM(x2);

    y1 = S.x.mul(c2).subM(x).mul(d);
    y2 = S.y.mul(c.square().mul(c));
    y  = y1.subM(y2);

    z  = S.z.mul(c);

    return new sjcl.ecc.pointJac(this.curve,x,y,z);
  },
  
  /**
   * doubles this point.
   * @return {sjcl.ecc.pointJac} The doubled point.
   */
  doubl: function() {
    if (this.isIdentity) { return this; }

    var
      y2 = this.y.square(),
      a  = y2.mul(this.x.mul(4)),
      b  = y2.square().mul(8),
      z2 = this.z.square(),
      c  = this.x.sub(z2).mul(3).mul(this.x.add(z2)),
      x  = c.square().subM(a).subM(a),
      y  = a.sub(x).mul(c).subM(b),
      z  = this.y.add(this.y).mul(this.z);
    return new sjcl.ecc.pointJac(this.curve, x, y, z);
  },

  /**
   * Returns a copy of this point converted to affine coordinates.
   * @return {sjcl.ecc.point} The converted point.
   */  
  toAffine: function() {
    if (this.isIdentity || this.z.equals(0)) {
      return new sjcl.ecc.point(this.curve);
    }
    var zi = this.z.inverse(), zi2 = zi.square();
    return new sjcl.ecc.point(this.curve, this.x.mul(zi2).fullReduce(), this.y.mul(zi2.mul(zi)).fullReduce());
  },
  
  /**
   * Multiply this point by k and return the answer in Jacobian coordinates.
   * @param {bigInt} k The coefficient to multiply by.
   * @param {sjcl.ecc.point} affine This point in affine coordinates.
   * @return {sjcl.ecc.pointJac} The result of the multiplication, in Jacobian coordinates.
   */
  mult: function(k, affine) {
    if (typeof(k) === "number") {
      k = [k];
    } else if (k.limbs !== undefined) {
      k = k.normalize().limbs;
    }
    
    var i, j, out = new sjcl.ecc.point(this.curve).toJac(), multiples = affine.multiples();

    for (i=k.length-1; i>=0; i--) {
      for (j=sjcl.bn.prototype.radix-4; j>=0; j-=4) {
        out = out.doubl().doubl().doubl().doubl().add(multiples[k[i]>>j & 0xF]);
      }
    }
    
    return out;
  },
  
  /**
   * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
   * @param {bigInt} k The coefficient to multiply this by.
   * @param {sjcl.ecc.point} affine This point in affine coordinates.
   * @param {bigInt} k2 The coefficient to multiply affine2 this by.
   * @param {sjcl.ecc.point} affine The other point in affine coordinates.
   * @return {sjcl.ecc.pointJac} The result of the multiplication and addition, in Jacobian coordinates.
   */
  mult2: function(k1, affine, k2, affine2) {
    if (typeof(k1) === "number") {
      k1 = [k1];
    } else if (k1.limbs !== undefined) {
      k1 = k1.normalize().limbs;
    }
    
    if (typeof(k2) === "number") {
      k2 = [k2];
    } else if (k2.limbs !== undefined) {
      k2 = k2.normalize().limbs;
    }
    
    var i, j, out = new sjcl.ecc.point(this.curve).toJac(), m1 = affine.multiples(),
        m2 = affine2.multiples(), l1, l2;

    for (i=Math.max(k1.length,k2.length)-1; i>=0; i--) {
      l1 = k1[i] | 0;
      l2 = k2[i] | 0;
      for (j=sjcl.bn.prototype.radix-4; j>=0; j-=4) {
        out = out.doubl().doubl().doubl().doubl().add(m1[l1>>j & 0xF]).add(m2[l2>>j & 0xF]);
      }
    }
    
    return out;
  },

  isValid: function() {
    var z2 = this.z.square(), z4 = z2.square(), z6 = z4.mul(z2);
    return this.y.square().equals(
             this.curve.b.mul(z6).add(this.x.mul(
               this.curve.a.mul(z4).add(this.x.square()))));
  }
};

/**
 * Construct an elliptic curve. Most users will not use this and instead start with one of the NIST curves defined below.
 *
 * @constructor
 * @param {bigInt} p The prime modulus.
 * @param {bigInt} pMinusR The modulus minus prime order of the curve.
 * @param {bigInt} a The constant a in the equation of the curve y^2 = x^3 + ax + b (for NIST curves, a is always -3).
 * @param {bigInt} x The x coordinate of a base point of the curve.
 * @param {bigInt} y The y coordinate of a base point of the curve.
 */
sjcl.ecc.curve = function(Field, pMinusR, a, b, x, y) {
  this.field = Field;
  this.r = Field.prototype.modulus.sub(pMinusR);
  this.a = new Field(a);
  this.b = new Field(b);
  this.G = new sjcl.ecc.point(this, new Field(x), new Field(y));
};

sjcl.ecc.curve.prototype.fromBits = function (bits) {
  var w = sjcl.bitArray, l = this.field.prototype.exponent + 7 & -8,
      p = new sjcl.ecc.point(this, this.field.fromBits(w.bitSlice(bits, 0, l)),
                             this.field.fromBits(w.bitSlice(bits, l, 2*l)));
  if (!p.isValid()) {
    throw new sjcl.exception.corrupt("not on the curve!");
  }
  return p;
};

sjcl.ecc.curves = {
  c192: new sjcl.ecc.curve(
    sjcl.bn.prime.p192,
    "0x662107c8eb94364e4b2dd7ce",
    -3,
    "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
    "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
    "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"),

  c224: new sjcl.ecc.curve(
    sjcl.bn.prime.p224,
    "0xe95c1f470fc1ec22d6baa3a3d5c4",
    -3,
    "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
    "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
    "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),

  c256: new sjcl.ecc.curve(
    sjcl.bn.prime.p256,
    "0x4319055358e8617b0c46353d039cdaae",
    -3,
    "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),

  c384: new sjcl.ecc.curve(
    sjcl.bn.prime.p384,
    "0x389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68c",
    -3,
    "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f")
};


/* Diffie-Hellman-like public-key system */
sjcl.ecc._dh = function(cn) {
    sjcl.ecc[cn] = {
	publicKey: function(curve_id, curve, point) {
	    this._curve = curve;

	    if (point instanceof Array) {
	        this._point = curve.fromBits(point);
	    } else {
	        this._point = point;
	    }

	    if (curve_id) {
	        this._curve_id = curve_id;
	        this.serialize = function() {
	            return {
			'point': point.toBits(),
	                'curve': curve_id
	            };
	        }
	    }
	},

	
	secretKey: function(curve_id, curve, exponent) {
	    this._curve = curve;
	    this._exponent = exponent;

	    if (curve_id) {
	        this._curve_id = curve_id;
	        this.serialize = function() {
	            return {
	                'exponent': exponent.toBits(),
	                'curve': curve_id
	            };
	        }
	    }
	},

	
	generateKeys: function(curve, paranoia) {
	    var curve_id;
	    if (curve === undefined) {
	        curve = 256;
	    }
	    if (typeof curve === "number") {
	        curve_id = curve;
	        curve = sjcl.ecc.curves['c' + curve];
	        if (curve === undefined) {
	            throw new sjcl.exception.invalid("no such curve");
	        }
	    }
	    var sec = sjcl.bn.random(curve.r, paranoia),
	    pub = curve.G.mult(sec);
	    return {
	        pub: new sjcl.ecc[cn].publicKey(curve_id, curve, pub),
	        sec: new sjcl.ecc[cn].secretKey(curve_id, curve, sec)
	    };
	}
    }; 
};

sjcl.ecc._dh("elGamal");

sjcl.ecc.elGamal.publicKey.prototype = {
  kem: function(paranoia) {
    var sec = sjcl.bn.random(this._curve.r, paranoia),
        tag = this._curve.G.mult(sec).toBits(),
        key = sjcl.hash.sha256.hash(this._point.mult(sec).toBits());
    return { key: key, tag: tag };
  }
};

sjcl.ecc.elGamal.secretKey.prototype = {
  unkem: function(tag) {
    return sjcl.hash.sha256.hash(this._curve.fromBits(tag).mult(this._exponent).toBits());
  },

  dh: function(pk) {
    return sjcl.hash.sha256.hash(pk._point.mult(this._exponent).toBits());
  }
};

sjcl.ecc._dh("ecdsa");

sjcl.ecc.ecdsa.secretKey.prototype = {
  sign: function(hash, paranoia) {
    var R = this._curve.r,
        l = R.bitLength(),
        k = sjcl.bn.random(R.sub(1), paranoia).add(1),
        r = this._curve.G.mult(k).x.mod(R),
        s = sjcl.bn.fromBits(hash).add(r.mul(this._exponent)).inverseMod(R).mul(k).mod(R);
    return sjcl.bitArray.concat(r.toBits(l), s.toBits(l));
  }
};

sjcl.ecc.ecdsa.publicKey.prototype = {
  verify: function(hash, rs) {
    var w = sjcl.bitArray,
        R = this._curve.r,
        l = R.bitLength(),
        r = sjcl.bn.fromBits(w.bitSlice(rs,0,l)),
        s = sjcl.bn.fromBits(w.bitSlice(rs,l,2*l)),
        hG = sjcl.bn.fromBits(hash).mul(s).mod(R),
        hA = r.mul(s).mod(R),
        r2 = this._curve.G.mult2(hG, hA, this._point).x;
        
    if (r.equals(0) || s.equals(0) || r.greaterEquals(R) || s.greaterEquals(R) || !r2.equals(r)) {
      throw (new sjcl.exception.corrupt("signature didn't check out"));
    }
    return true;
  }
};

/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Hexadecimal */
sjcl.codec.hex = {
  /** Convert from a bitArray to a hex string. */
  fromBits: function (arr) {
    var out = "", i, x;
    for (i=0; i<arr.length; i++) {
      out += ((arr[i]|0)+0xF00000000000).toString(16).substr(4);
    }
    return out.substr(0, sjcl.bitArray.bitLength(arr)/4);//.replace(/(.{8})/g, "$1 ");
  },
  /** Convert from a hex string to a bitArray. */
  toBits: function (str) {
    var i, out=[], len;
    str = str.replace(/\s|0x/g, "");
    len = str.length;
    str = str + "00000000";
    for (i=0; i<str.length; i+=8) {
      out.push(parseInt(str.substr(i,8),16)^0);
    }
    return sjcl.bitArray.clamp(out, len*4);
  }
};

/*! Socket.IO.js build:0.9.16, development. Copyright(c) 2011 LearnBoost <dev@learnboost.com> MIT Licensed */

var io = ('undefined' === typeof module ? {} : module.exports);
(function() {

/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

(function (exports, global) {

  /**
   * IO namespace.
   *
   * @namespace
   */

  var io = exports;

  /**
   * Socket.IO version
   *
   * @api public
   */

  io.version = '0.9.16';

  /**
   * Protocol implemented.
   *
   * @api public
   */

  io.protocol = 1;

  /**
   * Available transports, these will be populated with the available transports
   *
   * @api public
   */

  io.transports = [];

  /**
   * Keep track of jsonp callbacks.
   *
   * @api private
   */

  io.j = [];

  /**
   * Keep track of our io.Sockets
   *
   * @api private
   */
  io.sockets = {};


  /**
   * Manages connections to hosts.
   *
   * @param {String} uri
   * @Param {Boolean} force creation of new socket (defaults to false)
   * @api public
   */

  io.connect = function (host, details) {
    var uri = io.util.parseUri(host)
      , uuri
      , socket;

    if (global && global.location) {
      uri.protocol = uri.protocol || global.location.protocol.slice(0, -1);
      uri.host = uri.host || (global.document
        ? global.document.domain : global.location.hostname);
      uri.port = uri.port || global.location.port;
    }

    uuri = io.util.uniqueUri(uri);

    var options = {
        host: uri.host
      , secure: 'https' == uri.protocol
      , port: uri.port || ('https' == uri.protocol ? 443 : 80)
      , query: uri.query || ''
    };

    io.util.merge(options, details);

    if (options['force new connection'] || !io.sockets[uuri]) {
      socket = new io.Socket(options);
    }

    if (!options['force new connection'] && socket) {
      io.sockets[uuri] = socket;
    }

    socket = socket || io.sockets[uuri];

    // if path is different from '' or /
    return socket.of(uri.path.length > 1 ? uri.path : '');
  };

})('object' === typeof module ? module.exports : (this.io = {}), this);
/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

(function (exports, global) {

  /**
   * Utilities namespace.
   *
   * @namespace
   */

  var util = exports.util = {};

  /**
   * Parses an URI
   *
   * @author Steven Levithan <stevenlevithan.com> (MIT license)
   * @api public
   */

  var re = /^(?:(?![^:@]+:[^:@\/]*@)([^:\/?#.]+):)?(?:\/\/)?((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?)(((\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/;

  var parts = ['source', 'protocol', 'authority', 'userInfo', 'user', 'password',
               'host', 'port', 'relative', 'path', 'directory', 'file', 'query',
               'anchor'];

  util.parseUri = function (str) {
    var m = re.exec(str || '')
      , uri = {}
      , i = 14;

    while (i--) {
      uri[parts[i]] = m[i] || '';
    }

    return uri;
  };

  /**
   * Produces a unique url that identifies a Socket.IO connection.
   *
   * @param {Object} uri
   * @api public
   */

  util.uniqueUri = function (uri) {
    var protocol = uri.protocol
      , host = uri.host
      , port = uri.port;

    if ('document' in global) {
      host = host || document.domain;
      port = port || (protocol == 'https'
        && document.location.protocol !== 'https:' ? 443 : document.location.port);
    } else {
      host = host || 'localhost';

      if (!port && protocol == 'https') {
        port = 443;
      }
    }

    return (protocol || 'http') + '://' + host + ':' + (port || 80);
  };

  /**
   * Mergest 2 query strings in to once unique query string
   *
   * @param {String} base
   * @param {String} addition
   * @api public
   */

  util.query = function (base, addition) {
    var query = util.chunkQuery(base || '')
      , components = [];

    util.merge(query, util.chunkQuery(addition || ''));
    for (var part in query) {
      if (query.hasOwnProperty(part)) {
        components.push(part + '=' + query[part]);
      }
    }

    return components.length ? '?' + components.join('&') : '';
  };

  /**
   * Transforms a querystring in to an object
   *
   * @param {String} qs
   * @api public
   */

  util.chunkQuery = function (qs) {
    var query = {}
      , params = qs.split('&')
      , i = 0
      , l = params.length
      , kv;

    for (; i < l; ++i) {
      kv = params[i].split('=');
      if (kv[0]) {
        query[kv[0]] = kv[1];
      }
    }

    return query;
  };

  /**
   * Executes the given function when the page is loaded.
   *
   *     io.util.load(function () { console.log('page loaded'); });
   *
   * @param {Function} fn
   * @api public
   */

  var pageLoaded = false;

  util.load = function (fn) {
    if ('document' in global && document.readyState === 'complete' || pageLoaded) {
      return fn();
    }

    util.on(global, 'load', fn, false);
  };

  /**
   * Adds an event.
   *
   * @api private
   */

  util.on = function (element, event, fn, capture) {
    if (element.attachEvent) {
      element.attachEvent('on' + event, fn);
    } else if (element.addEventListener) {
      element.addEventListener(event, fn, capture);
    }
  };

  /**
   * Generates the correct `XMLHttpRequest` for regular and cross domain requests.
   *
   * @param {Boolean} [xdomain] Create a request that can be used cross domain.
   * @returns {XMLHttpRequest|false} If we can create a XMLHttpRequest.
   * @api private
   */

  util.request = function (xdomain) {

    if (xdomain && 'undefined' != typeof XDomainRequest && !util.ua.hasCORS) {
      return new XDomainRequest();
    }

    if ('undefined' != typeof XMLHttpRequest && (!xdomain || util.ua.hasCORS)) {
      return new XMLHttpRequest();
    }

    if (!xdomain) {
      try {
        return new window[(['Active'].concat('Object').join('X'))]('Microsoft.XMLHTTP');
      } catch(e) { }
    }

    return null;
  };

  /**
   * XHR based transport constructor.
   *
   * @constructor
   * @api public
   */

  /**
   * Change the internal pageLoaded value.
   */

  if ('undefined' != typeof window) {
    util.load(function () {
      pageLoaded = true;
    });
  }

  /**
   * Defers a function to ensure a spinner is not displayed by the browser
   *
   * @param {Function} fn
   * @api public
   */

  util.defer = function (fn) {
    if (!util.ua.webkit || 'undefined' != typeof importScripts) {
      return fn();
    }

    util.load(function () {
      setTimeout(fn, 100);
    });
  };

  /**
   * Merges two objects.
   *
   * @api public
   */

  util.merge = function merge (target, additional, deep, lastseen) {
    var seen = lastseen || []
      , depth = typeof deep == 'undefined' ? 2 : deep
      , prop;

    for (prop in additional) {
      if (additional.hasOwnProperty(prop) && util.indexOf(seen, prop) < 0) {
        if (typeof target[prop] !== 'object' || !depth) {
          target[prop] = additional[prop];
          seen.push(additional[prop]);
        } else {
          util.merge(target[prop], additional[prop], depth - 1, seen);
        }
      }
    }

    return target;
  };

  /**
   * Merges prototypes from objects
   *
   * @api public
   */

  util.mixin = function (ctor, ctor2) {
    util.merge(ctor.prototype, ctor2.prototype);
  };

  /**
   * Shortcut for prototypical and static inheritance.
   *
   * @api private
   */

  util.inherit = function (ctor, ctor2) {
    function f() {};
    f.prototype = ctor2.prototype;
    ctor.prototype = new f;
  };

  /**
   * Checks if the given object is an Array.
   *
   *     io.util.isArray([]); // true
   *     io.util.isArray({}); // false
   *
   * @param Object obj
   * @api public
   */

  util.isArray = Array.isArray || function (obj) {
    return Object.prototype.toString.call(obj) === '[object Array]';
  };

  /**
   * Intersects values of two arrays into a third
   *
   * @api public
   */

  util.intersect = function (arr, arr2) {
    var ret = []
      , longest = arr.length > arr2.length ? arr : arr2
      , shortest = arr.length > arr2.length ? arr2 : arr;

    for (var i = 0, l = shortest.length; i < l; i++) {
      if (~util.indexOf(longest, shortest[i]))
        ret.push(shortest[i]);
    }

    return ret;
  };

  /**
   * Array indexOf compatibility.
   *
   * @see bit.ly/a5Dxa2
   * @api public
   */

  util.indexOf = function (arr, o, i) {

    for (var j = arr.length, i = i < 0 ? i + j < 0 ? 0 : i + j : i || 0;
         i < j && arr[i] !== o; i++) {}

    return j <= i ? -1 : i;
  };

  /**
   * Converts enumerables to array.
   *
   * @api public
   */

  util.toArray = function (enu) {
    var arr = [];

    for (var i = 0, l = enu.length; i < l; i++)
      arr.push(enu[i]);

    return arr;
  };

  /**
   * UA / engines detection namespace.
   *
   * @namespace
   */

  util.ua = {};

  /**
   * Whether the UA supports CORS for XHR.
   *
   * @api public
   */

  util.ua.hasCORS = 'undefined' != typeof XMLHttpRequest && (function () {
    try {
      var a = new XMLHttpRequest();
    } catch (e) {
      return false;
    }

    return a.withCredentials != undefined;
  })();

  /**
   * Detect webkit.
   *
   * @api public
   */

  util.ua.webkit = 'undefined' != typeof navigator
    && /webkit/i.test(navigator.userAgent);

   /**
   * Detect iPad/iPhone/iPod.
   *
   * @api public
   */

  util.ua.iDevice = 'undefined' != typeof navigator
      && /iPad|iPhone|iPod/i.test(navigator.userAgent);

})('undefined' != typeof io ? io : module.exports, this);
/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

(function (exports, io) {

  /**
   * Expose constructor.
   */

  exports.EventEmitter = EventEmitter;

  /**
   * Event emitter constructor.
   *
   * @api public.
   */

  function EventEmitter () {};

  /**
   * Adds a listener
   *
   * @api public
   */

  EventEmitter.prototype.on = function (name, fn) {
    if (!this.$events) {
      this.$events = {};
    }

    if (!this.$events[name]) {
      this.$events[name] = fn;
    } else if (io.util.isArray(this.$events[name])) {
      this.$events[name].push(fn);
    } else {
      this.$events[name] = [this.$events[name], fn];
    }

    return this;
  };

  EventEmitter.prototype.addListener = EventEmitter.prototype.on;

  /**
   * Adds a volatile listener.
   *
   * @api public
   */

  EventEmitter.prototype.once = function (name, fn) {
    var self = this;

    function on () {
      self.removeListener(name, on);
      fn.apply(this, arguments);
    };

    on.listener = fn;
    this.on(name, on);

    return this;
  };

  /**
   * Removes a listener.
   *
   * @api public
   */

  EventEmitter.prototype.removeListener = function (name, fn) {
    if (this.$events && this.$events[name]) {
      var list = this.$events[name];

      if (io.util.isArray(list)) {
        var pos = -1;

        for (var i = 0, l = list.length; i < l; i++) {
          if (list[i] === fn || (list[i].listener && list[i].listener === fn)) {
            pos = i;
            break;
          }
        }

        if (pos < 0) {
          return this;
        }

        list.splice(pos, 1);

        if (!list.length) {
          delete this.$events[name];
        }
      } else if (list === fn || (list.listener && list.listener === fn)) {
        delete this.$events[name];
      }
    }

    return this;
  };

  /**
   * Removes all listeners for an event.
   *
   * @api public
   */

  EventEmitter.prototype.removeAllListeners = function (name) {
    if (name === undefined) {
      this.$events = {};
      return this;
    }

    if (this.$events && this.$events[name]) {
      this.$events[name] = null;
    }

    return this;
  };

  /**
   * Gets all listeners for a certain event.
   *
   * @api publci
   */

  EventEmitter.prototype.listeners = function (name) {
    if (!this.$events) {
      this.$events = {};
    }

    if (!this.$events[name]) {
      this.$events[name] = [];
    }

    if (!io.util.isArray(this.$events[name])) {
      this.$events[name] = [this.$events[name]];
    }

    return this.$events[name];
  };

  /**
   * Emits an event.
   *
   * @api public
   */

  EventEmitter.prototype.emit = function (name) {
    if (!this.$events) {
      return false;
    }

    var handler = this.$events[name];

    if (!handler) {
      return false;
    }

    var args = Array.prototype.slice.call(arguments, 1);

    if ('function' == typeof handler) {
      handler.apply(this, args);
    } else if (io.util.isArray(handler)) {
      var listeners = handler.slice();

      for (var i = 0, l = listeners.length; i < l; i++) {
        listeners[i].apply(this, args);
      }
    } else {
      return false;
    }

    return true;
  };

})(
    'undefined' != typeof io ? io : module.exports
  , 'undefined' != typeof io ? io : module.parent.exports
);

/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

/**
 * Based on JSON2 (http://www.JSON.org/js.html).
 */

(function (exports, nativeJSON) {
  "use strict";

  // use native JSON if it's available
  if (nativeJSON && nativeJSON.parse){
    return exports.JSON = {
      parse: nativeJSON.parse
    , stringify: nativeJSON.stringify
    };
  }

  var JSON = exports.JSON = {};

  function f(n) {
      // Format integers to have at least two digits.
      return n < 10 ? '0' + n : n;
  }

  function date(d, key) {
    return isFinite(d.valueOf()) ?
        d.getUTCFullYear()     + '-' +
        f(d.getUTCMonth() + 1) + '-' +
        f(d.getUTCDate())      + 'T' +
        f(d.getUTCHours())     + ':' +
        f(d.getUTCMinutes())   + ':' +
        f(d.getUTCSeconds())   + 'Z' : null;
  };

  var cx = /[\u0000\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,
      escapable = /[\\\"\x00-\x1f\x7f-\x9f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,
      gap,
      indent,
      meta = {    // table of character substitutions
          '\b': '\\b',
          '\t': '\\t',
          '\n': '\\n',
          '\f': '\\f',
          '\r': '\\r',
          '"' : '\\"',
          '\\': '\\\\'
      },
      rep;


  function quote(string) {

// If the string contains no control characters, no quote characters, and no
// backslash characters, then we can safely slap some quotes around it.
// Otherwise we must also replace the offending characters with safe escape
// sequences.

      escapable.lastIndex = 0;
      return escapable.test(string) ? '"' + string.replace(escapable, function (a) {
          var c = meta[a];
          return typeof c === 'string' ? c :
              '\\u' + ('0000' + a.charCodeAt(0).toString(16)).slice(-4);
      }) + '"' : '"' + string + '"';
  }


  function str(key, holder) {

// Produce a string from holder[key].

      var i,          // The loop counter.
          k,          // The member key.
          v,          // The member value.
          length,
          mind = gap,
          partial,
          value = holder[key];

// If the value has a toJSON method, call it to obtain a replacement value.

      if (value instanceof Date) {
          value = date(key);
      }

// If we were called with a replacer function, then call the replacer to
// obtain a replacement value.

      if (typeof rep === 'function') {
          value = rep.call(holder, key, value);
      }

// What happens next depends on the value's type.

      switch (typeof value) {
      case 'string':
          return quote(value);

      case 'number':

// JSON numbers must be finite. Encode non-finite numbers as null.

          return isFinite(value) ? String(value) : 'null';

      case 'boolean':
      case 'null':

// If the value is a boolean or null, convert it to a string. Note:
// typeof null does not produce 'null'. The case is included here in
// the remote chance that this gets fixed someday.

          return String(value);

// If the type is 'object', we might be dealing with an object or an array or
// null.

      case 'object':

// Due to a specification blunder in ECMAScript, typeof null is 'object',
// so watch out for that case.

          if (!value) {
              return 'null';
          }

// Make an array to hold the partial results of stringifying this object value.

          gap += indent;
          partial = [];

// Is the value an array?

          if (Object.prototype.toString.apply(value) === '[object Array]') {

// The value is an array. Stringify every element. Use null as a placeholder
// for non-JSON values.

              length = value.length;
              for (i = 0; i < length; i += 1) {
                  partial[i] = str(i, value) || 'null';
              }

// Join all of the elements together, separated with commas, and wrap them in
// brackets.

              v = partial.length === 0 ? '[]' : gap ?
                  '[\n' + gap + partial.join(',\n' + gap) + '\n' + mind + ']' :
                  '[' + partial.join(',') + ']';
              gap = mind;
              return v;
          }

// If the replacer is an array, use it to select the members to be stringified.

          if (rep && typeof rep === 'object') {
              length = rep.length;
              for (i = 0; i < length; i += 1) {
                  if (typeof rep[i] === 'string') {
                      k = rep[i];
                      v = str(k, value);
                      if (v) {
                          partial.push(quote(k) + (gap ? ': ' : ':') + v);
                      }
                  }
              }
          } else {

// Otherwise, iterate through all of the keys in the object.

              for (k in value) {
                  if (Object.prototype.hasOwnProperty.call(value, k)) {
                      v = str(k, value);
                      if (v) {
                          partial.push(quote(k) + (gap ? ': ' : ':') + v);
                      }
                  }
              }
          }

// Join all of the member texts together, separated with commas,
// and wrap them in braces.

          v = partial.length === 0 ? '{}' : gap ?
              '{\n' + gap + partial.join(',\n' + gap) + '\n' + mind + '}' :
              '{' + partial.join(',') + '}';
          gap = mind;
          return v;
      }
  }

// If the JSON object does not yet have a stringify method, give it one.

  JSON.stringify = function (value, replacer, space) {

// The stringify method takes a value and an optional replacer, and an optional
// space parameter, and returns a JSON text. The replacer can be a function
// that can replace values, or an array of strings that will select the keys.
// A default replacer method can be provided. Use of the space parameter can
// produce text that is more easily readable.

      var i;
      gap = '';
      indent = '';

// If the space parameter is a number, make an indent string containing that
// many spaces.

      if (typeof space === 'number') {
          for (i = 0; i < space; i += 1) {
              indent += ' ';
          }

// If the space parameter is a string, it will be used as the indent string.

      } else if (typeof space === 'string') {
          indent = space;
      }

// If there is a replacer, it must be a function or an array.
// Otherwise, throw an error.

      rep = replacer;
      if (replacer && typeof replacer !== 'function' &&
              (typeof replacer !== 'object' ||
              typeof replacer.length !== 'number')) {
          throw new Error('JSON.stringify');
      }

// Make a fake root object containing our value under the key of ''.
// Return the result of stringifying the value.

      return str('', {'': value});
  };

// If the JSON object does not yet have a parse method, give it one.

  JSON.parse = function (text, reviver) {
  // The parse method takes a text and an optional reviver function, and returns
  // a JavaScript value if the text is a valid JSON text.

      var j;

      function walk(holder, key) {

  // The walk method is used to recursively walk the resulting structure so
  // that modifications can be made.

          var k, v, value = holder[key];
          if (value && typeof value === 'object') {
              for (k in value) {
                  if (Object.prototype.hasOwnProperty.call(value, k)) {
                      v = walk(value, k);
                      if (v !== undefined) {
                          value[k] = v;
                      } else {
                          delete value[k];
                      }
                  }
              }
          }
          return reviver.call(holder, key, value);
      }


  // Parsing happens in four stages. In the first stage, we replace certain
  // Unicode characters with escape sequences. JavaScript handles many characters
  // incorrectly, either silently deleting them, or treating them as line endings.

      text = String(text);
      cx.lastIndex = 0;
      if (cx.test(text)) {
          text = text.replace(cx, function (a) {
              return '\\u' +
                  ('0000' + a.charCodeAt(0).toString(16)).slice(-4);
          });
      }

  // In the second stage, we run the text against regular expressions that look
  // for non-JSON patterns. We are especially concerned with '()' and 'new'
  // because they can cause invocation, and '=' because it can cause mutation.
  // But just to be safe, we want to reject all unexpected forms.

  // We split the second stage into 4 regexp operations in order to work around
  // crippling inefficiencies in IE's and Safari's regexp engines. First we
  // replace the JSON backslash pairs with '@' (a non-JSON character). Second, we
  // replace all simple value tokens with ']' characters. Third, we delete all
  // open brackets that follow a colon or comma or that begin the text. Finally,
  // we look to see that the remaining characters are only whitespace or ']' or
  // ',' or ':' or '{' or '}'. If that is so, then the text is safe for eval.

      if (/^[\],:{}\s]*$/
              .test(text.replace(/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g, '@')
                  .replace(/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g, ']')
                  .replace(/(?:^|:|,)(?:\s*\[)+/g, ''))) {

  // In the third stage we use the eval function to compile the text into a
  // JavaScript structure. The '{' operator is subject to a syntactic ambiguity
  // in JavaScript: it can begin a block or an object literal. We wrap the text
  // in parens to eliminate the ambiguity.

          j = eval('(' + text + ')');

  // In the optional fourth stage, we recursively walk the new structure, passing
  // each name/value pair to a reviver function for possible transformation.

          return typeof reviver === 'function' ?
              walk({'': j}, '') : j;
      }

  // If the text is not JSON parseable, then a SyntaxError is thrown.

      throw new SyntaxError('JSON.parse');
  };

})(
    'undefined' != typeof io ? io : module.exports
  , typeof JSON !== 'undefined' ? JSON : undefined
);

/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

(function (exports, io) {

  /**
   * Parser namespace.
   *
   * @namespace
   */

  var parser = exports.parser = {};

  /**
   * Packet types.
   */

  var packets = parser.packets = [
      'disconnect'
    , 'connect'
    , 'heartbeat'
    , 'message'
    , 'json'
    , 'event'
    , 'ack'
    , 'error'
    , 'noop'
  ];

  /**
   * Errors reasons.
   */

  var reasons = parser.reasons = [
      'transport not supported'
    , 'client not handshaken'
    , 'unauthorized'
  ];

  /**
   * Errors advice.
   */

  var advice = parser.advice = [
      'reconnect'
  ];

  /**
   * Shortcuts.
   */

  var JSON = io.JSON
    , indexOf = io.util.indexOf;

  /**
   * Encodes a packet.
   *
   * @api private
   */

  parser.encodePacket = function (packet) {
    var type = indexOf(packets, packet.type)
      , id = packet.id || ''
      , endpoint = packet.endpoint || ''
      , ack = packet.ack
      , data = null;

    switch (packet.type) {
      case 'error':
        var reason = packet.reason ? indexOf(reasons, packet.reason) : ''
          , adv = packet.advice ? indexOf(advice, packet.advice) : '';

        if (reason !== '' || adv !== '')
          data = reason + (adv !== '' ? ('+' + adv) : '');

        break;

      case 'message':
        if (packet.data !== '')
          data = packet.data;
        break;

      case 'event':
        var ev = { name: packet.name };

        if (packet.args && packet.args.length) {
          ev.args = packet.args;
        }

        data = JSON.stringify(ev);
        break;

      case 'json':
        data = JSON.stringify(packet.data);
        break;

      case 'connect':
        if (packet.qs)
          data = packet.qs;
        break;

      case 'ack':
        data = packet.ackId
          + (packet.args && packet.args.length
              ? '+' + JSON.stringify(packet.args) : '');
        break;
    }

    // construct packet with required fragments
    var encoded = [
        type
      , id + (ack == 'data' ? '+' : '')
      , endpoint
    ];

    // data fragment is optional
    if (data !== null && data !== undefined)
      encoded.push(data);

    return encoded.join(':');
  };

  /**
   * Encodes multiple messages (payload).
   *
   * @param {Array} messages
   * @api private
   */

  parser.encodePayload = function (packets) {
    var decoded = '';

    if (packets.length == 1)
      return packets[0];

    for (var i = 0, l = packets.length; i < l; i++) {
      var packet = packets[i];
      decoded += '\ufffd' + packet.length + '\ufffd' + packets[i];
    }

    return decoded;
  };

  /**
   * Decodes a packet
   *
   * @api private
   */

  var regexp = /([^:]+):([0-9]+)?(\+)?:([^:]+)?:?([\s\S]*)?/;

  parser.decodePacket = function (data) {
    var pieces = data.match(regexp);

    if (!pieces) return {};

    var id = pieces[2] || ''
      , data = pieces[5] || ''
      , packet = {
            type: packets[pieces[1]]
          , endpoint: pieces[4] || ''
        };

    // whether we need to acknowledge the packet
    if (id) {
      packet.id = id;
      if (pieces[3])
        packet.ack = 'data';
      else
        packet.ack = true;
    }

    // handle different packet types
    switch (packet.type) {
      case 'error':
        var pieces = data.split('+');
        packet.reason = reasons[pieces[0]] || '';
        packet.advice = advice[pieces[1]] || '';
        break;

      case 'message':
        packet.data = data || '';
        break;

      case 'event':
        try {
          var opts = JSON.parse(data);
          packet.name = opts.name;
          packet.args = opts.args;
        } catch (e) { }

        packet.args = packet.args || [];
        break;

      case 'json':
        try {
          packet.data = JSON.parse(data);
        } catch (e) { }
        break;

      case 'connect':
        packet.qs = data || '';
        break;

      case 'ack':
        var pieces = data.match(/^([0-9]+)(\+)?(.*)/);
        if (pieces) {
          packet.ackId = pieces[1];
          packet.args = [];

          if (pieces[3]) {
            try {
              packet.args = pieces[3] ? JSON.parse(pieces[3]) : [];
            } catch (e) { }
          }
        }
        break;

      case 'disconnect':
      case 'heartbeat':
        break;
    };

    return packet;
  };

  /**
   * Decodes data payload. Detects multiple messages
   *
   * @return {Array} messages
   * @api public
   */

  parser.decodePayload = function (data) {
    // IE doesn't like data[i] for unicode chars, charAt works fine
    if (data.charAt(0) == '\ufffd') {
      var ret = [];

      for (var i = 1, length = ''; i < data.length; i++) {
        if (data.charAt(i) == '\ufffd') {
          ret.push(parser.decodePacket(data.substr(i + 1).substr(0, length)));
          i += Number(length) + 1;
          length = '';
        } else {
          length += data.charAt(i);
        }
      }

      return ret;
    } else {
      return [parser.decodePacket(data)];
    }
  };

})(
    'undefined' != typeof io ? io : module.exports
  , 'undefined' != typeof io ? io : module.parent.exports
);
/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

(function (exports, io) {

  /**
   * Expose constructor.
   */

  exports.Transport = Transport;

  /**
   * This is the transport template for all supported transport methods.
   *
   * @constructor
   * @api public
   */

  function Transport (socket, sessid) {
    this.socket = socket;
    this.sessid = sessid;
  };

  /**
   * Apply EventEmitter mixin.
   */

  io.util.mixin(Transport, io.EventEmitter);


  /**
   * Indicates whether heartbeats is enabled for this transport
   *
   * @api private
   */

  Transport.prototype.heartbeats = function () {
    return true;
  };

  /**
   * Handles the response from the server. When a new response is received
   * it will automatically update the timeout, decode the message and
   * forwards the response to the onMessage function for further processing.
   *
   * @param {String} data Response from the server.
   * @api private
   */

  Transport.prototype.onData = function (data) {
    this.clearCloseTimeout();

    // If the connection in currently open (or in a reopening state) reset the close
    // timeout since we have just received data. This check is necessary so
    // that we don't reset the timeout on an explicitly disconnected connection.
    if (this.socket.connected || this.socket.connecting || this.socket.reconnecting) {
      this.setCloseTimeout();
    }

    if (data !== '') {
      // todo: we should only do decodePayload for xhr transports
      var msgs = io.parser.decodePayload(data);

      if (msgs && msgs.length) {
        for (var i = 0, l = msgs.length; i < l; i++) {
          this.onPacket(msgs[i]);
        }
      }
    }

    return this;
  };

  /**
   * Handles packets.
   *
   * @api private
   */

  Transport.prototype.onPacket = function (packet) {
    this.socket.setHeartbeatTimeout();

    if (packet.type == 'heartbeat') {
      return this.onHeartbeat();
    }

    if (packet.type == 'connect' && packet.endpoint == '') {
      this.onConnect();
    }

    if (packet.type == 'error' && packet.advice == 'reconnect') {
      this.isOpen = false;
    }

    this.socket.onPacket(packet);

    return this;
  };

  /**
   * Sets close timeout
   *
   * @api private
   */

  Transport.prototype.setCloseTimeout = function () {
    if (!this.closeTimeout) {
      var self = this;

      this.closeTimeout = setTimeout(function () {
        self.onDisconnect();
      }, this.socket.closeTimeout);
    }
  };

  /**
   * Called when transport disconnects.
   *
   * @api private
   */

  Transport.prototype.onDisconnect = function () {
    if (this.isOpen) this.close();
    this.clearTimeouts();
    this.socket.onDisconnect();
    return this;
  };

  /**
   * Called when transport connects
   *
   * @api private
   */

  Transport.prototype.onConnect = function () {
    this.socket.onConnect();
    return this;
  };

  /**
   * Clears close timeout
   *
   * @api private
   */

  Transport.prototype.clearCloseTimeout = function () {
    if (this.closeTimeout) {
      clearTimeout(this.closeTimeout);
      this.closeTimeout = null;
    }
  };

  /**
   * Clear timeouts
   *
   * @api private
   */

  Transport.prototype.clearTimeouts = function () {
    this.clearCloseTimeout();

    if (this.reopenTimeout) {
      clearTimeout(this.reopenTimeout);
    }
  };

  /**
   * Sends a packet
   *
   * @param {Object} packet object.
   * @api private
   */

  Transport.prototype.packet = function (packet) {
    this.send(io.parser.encodePacket(packet));
  };

  /**
   * Send the received heartbeat message back to server. So the server
   * knows we are still connected.
   *
   * @param {String} heartbeat Heartbeat response from the server.
   * @api private
   */

  Transport.prototype.onHeartbeat = function (heartbeat) {
    this.packet({ type: 'heartbeat' });
  };

  /**
   * Called when the transport opens.
   *
   * @api private
   */

  Transport.prototype.onOpen = function () {
    this.isOpen = true;
    this.clearCloseTimeout();
    this.socket.onOpen();
  };

  /**
   * Notifies the base when the connection with the Socket.IO server
   * has been disconnected.
   *
   * @api private
   */

  Transport.prototype.onClose = function () {
    var self = this;

    /* FIXME: reopen delay causing a infinit loop
    this.reopenTimeout = setTimeout(function () {
      self.open();
    }, this.socket.options['reopen delay']);*/

    this.isOpen = false;
    this.socket.onClose();
    this.onDisconnect();
  };

  /**
   * Generates a connection url based on the Socket.IO URL Protocol.
   * See <https://github.com/learnboost/socket.io-node/> for more details.
   *
   * @returns {String} Connection url
   * @api private
   */

  Transport.prototype.prepareUrl = function () {
    var options = this.socket.options;

    return this.scheme() + '://'
      + options.host + ':' + options.port + '/'
      + options.resource + '/' + io.protocol
      + '/' + this.name + '/' + this.sessid;
  };

  /**
   * Checks if the transport is ready to start a connection.
   *
   * @param {Socket} socket The socket instance that needs a transport
   * @param {Function} fn The callback
   * @api private
   */

  Transport.prototype.ready = function (socket, fn) {
    fn.call(this);
  };
})(
    'undefined' != typeof io ? io : module.exports
  , 'undefined' != typeof io ? io : module.parent.exports
);
/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

(function (exports, io, global) {

  /**
   * Expose constructor.
   */

  exports.Socket = Socket;

  /**
   * Create a new `Socket.IO client` which can establish a persistent
   * connection with a Socket.IO enabled server.
   *
   * @api public
   */

  function Socket (options) {
    this.options = {
        port: 80
      , secure: false
      , document: 'document' in global ? document : false
      , resource: 'socket.io'
      , transports: io.transports
      , 'connect timeout': 10000
      , 'try multiple transports': true
      , 'reconnect': true
      , 'reconnection delay': 500
      , 'reconnection limit': Infinity
      , 'reopen delay': 3000
      , 'max reconnection attempts': 10
      , 'sync disconnect on unload': false
      , 'auto connect': true
      , 'flash policy port': 10843
      , 'manualFlush': false
    };

    io.util.merge(this.options, options);

    this.connected = false;
    this.open = false;
    this.connecting = false;
    this.reconnecting = false;
    this.namespaces = {};
    this.buffer = [];
    this.doBuffer = false;

    if (this.options['sync disconnect on unload'] &&
        (!this.isXDomain() || io.util.ua.hasCORS)) {
      var self = this;
      io.util.on(global, 'beforeunload', function () {
        self.disconnectSync();
      }, false);
    }

    if (this.options['auto connect']) {
      this.connect();
    }
};

  /**
   * Apply EventEmitter mixin.
   */

  io.util.mixin(Socket, io.EventEmitter);

  /**
   * Returns a namespace listener/emitter for this socket
   *
   * @api public
   */

  Socket.prototype.of = function (name) {
    if (!this.namespaces[name]) {
      this.namespaces[name] = new io.SocketNamespace(this, name);

      if (name !== '') {
        this.namespaces[name].packet({ type: 'connect' });
      }
    }

    return this.namespaces[name];
  };

  /**
   * Emits the given event to the Socket and all namespaces
   *
   * @api private
   */

  Socket.prototype.publish = function () {
    this.emit.apply(this, arguments);

    var nsp;

    for (var i in this.namespaces) {
      if (this.namespaces.hasOwnProperty(i)) {
        nsp = this.of(i);
        nsp.$emit.apply(nsp, arguments);
      }
    }
  };

  /**
   * Performs the handshake
   *
   * @api private
   */

  function empty () { };

  Socket.prototype.handshake = function (fn) {
    var self = this
      , options = this.options;

    function complete (data) {
      if (data instanceof Error) {
        self.connecting = false;
        self.onError(data.message);
      } else {
        fn.apply(null, data.split(':'));
      }
    };

    var url = [
          'http' + (options.secure ? 's' : '') + ':/'
        , options.host + ':' + options.port
        , options.resource
        , io.protocol
        , io.util.query(this.options.query, 't=' + +new Date)
      ].join('/');

    if (this.isXDomain() && !io.util.ua.hasCORS) {
      var insertAt = document.getElementsByTagName('script')[0]
        , script = document.createElement('script');

      script.src = url + '&jsonp=' + io.j.length;
      insertAt.parentNode.insertBefore(script, insertAt);

      io.j.push(function (data) {
        complete(data);
        script.parentNode.removeChild(script);
      });
    } else {
      var xhr = io.util.request();

      xhr.open('GET', url, true);
      if (this.isXDomain()) {
        xhr.withCredentials = true;
      }
      xhr.onreadystatechange = function () {
        if (xhr.readyState == 4) {
          xhr.onreadystatechange = empty;

          if (xhr.status == 200) {
            complete(xhr.responseText);
          } else if (xhr.status == 403) {
            self.onError(xhr.responseText);
          } else {
            self.connecting = false;            
            !self.reconnecting && self.onError(xhr.responseText);
          }
        }
      };
      xhr.send(null);
    }
  };

  /**
   * Find an available transport based on the options supplied in the constructor.
   *
   * @api private
   */

  Socket.prototype.getTransport = function (override) {
    var transports = override || this.transports, match;

    for (var i = 0, transport; transport = transports[i]; i++) {
      if (io.Transport[transport]
        && io.Transport[transport].check(this)
        && (!this.isXDomain() || io.Transport[transport].xdomainCheck(this))) {
        return new io.Transport[transport](this, this.sessionid);
      }
    }

    return null;
  };

  /**
   * Connects to the server.
   *
   * @param {Function} [fn] Callback.
   * @returns {io.Socket}
   * @api public
   */

  Socket.prototype.connect = function (fn) {
    if (this.connecting) {
      return this;
    }

    var self = this;
    self.connecting = true;
    
    this.handshake(function (sid, heartbeat, close, transports) {
      self.sessionid = sid;
      self.closeTimeout = close * 1000;
      self.heartbeatTimeout = heartbeat * 1000;
      if(!self.transports)
          self.transports = self.origTransports = (transports ? io.util.intersect(
              transports.split(',')
            , self.options.transports
          ) : self.options.transports);

      self.setHeartbeatTimeout();

      function connect (transports){
        if (self.transport) self.transport.clearTimeouts();

        self.transport = self.getTransport(transports);
        if (!self.transport) return self.publish('connect_failed');

        // once the transport is ready
        self.transport.ready(self, function () {
          self.connecting = true;
          self.publish('connecting', self.transport.name);
          self.transport.open();

          if (self.options['connect timeout']) {
            self.connectTimeoutTimer = setTimeout(function () {
              if (!self.connected) {
                self.connecting = false;

                if (self.options['try multiple transports']) {
                  var remaining = self.transports;

                  while (remaining.length > 0 && remaining.splice(0,1)[0] !=
                         self.transport.name) {}

                    if (remaining.length){
                      connect(remaining);
                    } else {
                      self.publish('connect_failed');
                    }
                }
              }
            }, self.options['connect timeout']);
          }
        });
      }

      connect(self.transports);

      self.once('connect', function (){
        clearTimeout(self.connectTimeoutTimer);

        fn && typeof fn == 'function' && fn();
      });
    });

    return this;
  };

  /**
   * Clears and sets a new heartbeat timeout using the value given by the
   * server during the handshake.
   *
   * @api private
   */

  Socket.prototype.setHeartbeatTimeout = function () {
    clearTimeout(this.heartbeatTimeoutTimer);
    if(this.transport && !this.transport.heartbeats()) return;

    var self = this;
    this.heartbeatTimeoutTimer = setTimeout(function () {
      self.transport.onClose();
    }, this.heartbeatTimeout);
  };

  /**
   * Sends a message.
   *
   * @param {Object} data packet.
   * @returns {io.Socket}
   * @api public
   */

  Socket.prototype.packet = function (data) {
    if (this.connected && !this.doBuffer) {
      this.transport.packet(data);
    } else {
      this.buffer.push(data);
    }

    return this;
  };

  /**
   * Sets buffer state
   *
   * @api private
   */

  Socket.prototype.setBuffer = function (v) {
    this.doBuffer = v;

    if (!v && this.connected && this.buffer.length) {
      if (!this.options['manualFlush']) {
        this.flushBuffer();
      }
    }
  };

  /**
   * Flushes the buffer data over the wire.
   * To be invoked manually when 'manualFlush' is set to true.
   *
   * @api public
   */

  Socket.prototype.flushBuffer = function() {
    this.transport.payload(this.buffer);
    this.buffer = [];
  };
  

  /**
   * Disconnect the established connect.
   *
   * @returns {io.Socket}
   * @api public
   */

  Socket.prototype.disconnect = function () {
    if (this.connected || this.connecting) {
      if (this.open) {
        this.of('').packet({ type: 'disconnect' });
      }

      // handle disconnection immediately
      this.onDisconnect('booted');
    }

    return this;
  };

  /**
   * Disconnects the socket with a sync XHR.
   *
   * @api private
   */

  Socket.prototype.disconnectSync = function () {
    // ensure disconnection
    var xhr = io.util.request();
    var uri = [
        'http' + (this.options.secure ? 's' : '') + ':/'
      , this.options.host + ':' + this.options.port
      , this.options.resource
      , io.protocol
      , ''
      , this.sessionid
    ].join('/') + '/?disconnect=1';

    xhr.open('GET', uri, false);
    xhr.send(null);

    // handle disconnection immediately
    this.onDisconnect('booted');
  };

  /**
   * Check if we need to use cross domain enabled transports. Cross domain would
   * be a different port or different domain name.
   *
   * @returns {Boolean}
   * @api private
   */

  Socket.prototype.isXDomain = function () {

    var port = global.location.port ||
      ('https:' == global.location.protocol ? 443 : 80);

    return this.options.host !== global.location.hostname 
      || this.options.port != port;
  };

  /**
   * Called upon handshake.
   *
   * @api private
   */

  Socket.prototype.onConnect = function () {
    if (!this.connected) {
      this.connected = true;
      this.connecting = false;
      if (!this.doBuffer) {
        // make sure to flush the buffer
        this.setBuffer(false);
      }
      this.emit('connect');
    }
  };

  /**
   * Called when the transport opens
   *
   * @api private
   */

  Socket.prototype.onOpen = function () {
    this.open = true;
  };

  /**
   * Called when the transport closes.
   *
   * @api private
   */

  Socket.prototype.onClose = function () {
    this.open = false;
    clearTimeout(this.heartbeatTimeoutTimer);
  };

  /**
   * Called when the transport first opens a connection
   *
   * @param text
   */

  Socket.prototype.onPacket = function (packet) {
    this.of(packet.endpoint).onPacket(packet);
  };

  /**
   * Handles an error.
   *
   * @api private
   */

  Socket.prototype.onError = function (err) {
    if (err && err.advice) {
      if (err.advice === 'reconnect' && (this.connected || this.connecting)) {
        this.disconnect();
        if (this.options.reconnect) {
          this.reconnect();
        }
      }
    }

    this.publish('error', err && err.reason ? err.reason : err);
  };

  /**
   * Called when the transport disconnects.
   *
   * @api private
   */

  Socket.prototype.onDisconnect = function (reason) {
    var wasConnected = this.connected
      , wasConnecting = this.connecting;

    this.connected = false;
    this.connecting = false;
    this.open = false;

    if (wasConnected || wasConnecting) {
      this.transport.close();
      this.transport.clearTimeouts();
      if (wasConnected) {
        this.publish('disconnect', reason);

        if ('booted' != reason && this.options.reconnect && !this.reconnecting) {
          this.reconnect();
        }
      }
    }
  };

  /**
   * Called upon reconnection.
   *
   * @api private
   */

  Socket.prototype.reconnect = function () {
    this.reconnecting = true;
    this.reconnectionAttempts = 0;
    this.reconnectionDelay = this.options['reconnection delay'];

    var self = this
      , maxAttempts = this.options['max reconnection attempts']
      , tryMultiple = this.options['try multiple transports']
      , limit = this.options['reconnection limit'];

    function reset () {
      if (self.connected) {
        for (var i in self.namespaces) {
          if (self.namespaces.hasOwnProperty(i) && '' !== i) {
              self.namespaces[i].packet({ type: 'connect' });
          }
        }
        self.publish('reconnect', self.transport.name, self.reconnectionAttempts);
      }

      clearTimeout(self.reconnectionTimer);

      self.removeListener('connect_failed', maybeReconnect);
      self.removeListener('connect', maybeReconnect);

      self.reconnecting = false;

      delete self.reconnectionAttempts;
      delete self.reconnectionDelay;
      delete self.reconnectionTimer;
      delete self.redoTransports;

      self.options['try multiple transports'] = tryMultiple;
    };

    function maybeReconnect () {
      if (!self.reconnecting) {
        return;
      }

      if (self.connected) {
        return reset();
      };

      if (self.connecting && self.reconnecting) {
        return self.reconnectionTimer = setTimeout(maybeReconnect, 1000);
      }

      if (self.reconnectionAttempts++ >= maxAttempts) {
        if (!self.redoTransports) {
          self.on('connect_failed', maybeReconnect);
          self.options['try multiple transports'] = true;
          self.transports = self.origTransports;
          self.transport = self.getTransport();
          self.redoTransports = true;
          self.connect();
        } else {
          self.publish('reconnect_failed');
          reset();
        }
      } else {
        if (self.reconnectionDelay < limit) {
          self.reconnectionDelay *= 2; // exponential back off
        }

        self.connect();
        self.publish('reconnecting', self.reconnectionDelay, self.reconnectionAttempts);
        self.reconnectionTimer = setTimeout(maybeReconnect, self.reconnectionDelay);
      }
    };

    this.options['try multiple transports'] = false;
    this.reconnectionTimer = setTimeout(maybeReconnect, this.reconnectionDelay);

    this.on('connect', maybeReconnect);
  };

})(
    'undefined' != typeof io ? io : module.exports
  , 'undefined' != typeof io ? io : module.parent.exports
  , this
);
/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

(function (exports, io) {

  /**
   * Expose constructor.
   */

  exports.SocketNamespace = SocketNamespace;

  /**
   * Socket namespace constructor.
   *
   * @constructor
   * @api public
   */

  function SocketNamespace (socket, name) {
    this.socket = socket;
    this.name = name || '';
    this.flags = {};
    this.json = new Flag(this, 'json');
    this.ackPackets = 0;
    this.acks = {};
  };

  /**
   * Apply EventEmitter mixin.
   */

  io.util.mixin(SocketNamespace, io.EventEmitter);

  /**
   * Copies emit since we override it
   *
   * @api private
   */

  SocketNamespace.prototype.$emit = io.EventEmitter.prototype.emit;

  /**
   * Creates a new namespace, by proxying the request to the socket. This
   * allows us to use the synax as we do on the server.
   *
   * @api public
   */

  SocketNamespace.prototype.of = function () {
    return this.socket.of.apply(this.socket, arguments);
  };

  /**
   * Sends a packet.
   *
   * @api private
   */

  SocketNamespace.prototype.packet = function (packet) {
    packet.endpoint = this.name;
    this.socket.packet(packet);
    this.flags = {};
    return this;
  };

  /**
   * Sends a message
   *
   * @api public
   */

  SocketNamespace.prototype.send = function (data, fn) {
    var packet = {
        type: this.flags.json ? 'json' : 'message'
      , data: data
    };

    if ('function' == typeof fn) {
      packet.id = ++this.ackPackets;
      packet.ack = true;
      this.acks[packet.id] = fn;
    }

    return this.packet(packet);
  };

  /**
   * Emits an event
   *
   * @api public
   */
  
  SocketNamespace.prototype.emit = function (name) {
    var args = Array.prototype.slice.call(arguments, 1)
      , lastArg = args[args.length - 1]
      , packet = {
            type: 'event'
          , name: name
        };

    if ('function' == typeof lastArg) {
      packet.id = ++this.ackPackets;
      packet.ack = 'data';
      this.acks[packet.id] = lastArg;
      args = args.slice(0, args.length - 1);
    }

    packet.args = args;

    return this.packet(packet);
  };

  /**
   * Disconnects the namespace
   *
   * @api private
   */

  SocketNamespace.prototype.disconnect = function () {
    if (this.name === '') {
      this.socket.disconnect();
    } else {
      this.packet({ type: 'disconnect' });
      this.$emit('disconnect');
    }

    return this;
  };

  /**
   * Handles a packet
   *
   * @api private
   */

  SocketNamespace.prototype.onPacket = function (packet) {
    var self = this;

    function ack () {
      self.packet({
          type: 'ack'
        , args: io.util.toArray(arguments)
        , ackId: packet.id
      });
    };

    switch (packet.type) {
      case 'connect':
        this.$emit('connect');
        break;

      case 'disconnect':
        if (this.name === '') {
          this.socket.onDisconnect(packet.reason || 'booted');
        } else {
          this.$emit('disconnect', packet.reason);
        }
        break;

      case 'message':
      case 'json':
        var params = ['message', packet.data];

        if (packet.ack == 'data') {
          params.push(ack);
        } else if (packet.ack) {
          this.packet({ type: 'ack', ackId: packet.id });
        }

        this.$emit.apply(this, params);
        break;

      case 'event':
        var params = [packet.name].concat(packet.args);

        if (packet.ack == 'data')
          params.push(ack);

        this.$emit.apply(this, params);
        break;

      case 'ack':
        if (this.acks[packet.ackId]) {
          this.acks[packet.ackId].apply(this, packet.args);
          delete this.acks[packet.ackId];
        }
        break;

      case 'error':
        if (packet.advice){
          this.socket.onError(packet);
        } else {
          if (packet.reason == 'unauthorized') {
            this.$emit('connect_failed', packet.reason);
          } else {
            this.$emit('error', packet.reason);
          }
        }
        break;
    }
  };

  /**
   * Flag interface.
   *
   * @api private
   */

  function Flag (nsp, name) {
    this.namespace = nsp;
    this.name = name;
  };

  /**
   * Send a message
   *
   * @api public
   */

  Flag.prototype.send = function () {
    this.namespace.flags[this.name] = true;
    this.namespace.send.apply(this.namespace, arguments);
  };

  /**
   * Emit an event
   *
   * @api public
   */

  Flag.prototype.emit = function () {
    this.namespace.flags[this.name] = true;
    this.namespace.emit.apply(this.namespace, arguments);
  };

})(
    'undefined' != typeof io ? io : module.exports
  , 'undefined' != typeof io ? io : module.parent.exports
);

/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

(function (exports, io, global) {

  /**
   * Expose constructor.
   */

  exports.websocket = WS;

  /**
   * The WebSocket transport uses the HTML5 WebSocket API to establish an
   * persistent connection with the Socket.IO server. This transport will also
   * be inherited by the FlashSocket fallback as it provides a API compatible
   * polyfill for the WebSockets.
   *
   * @constructor
   * @extends {io.Transport}
   * @api public
   */

  function WS (socket) {
    io.Transport.apply(this, arguments);
  };

  /**
   * Inherits from Transport.
   */

  io.util.inherit(WS, io.Transport);

  /**
   * Transport name
   *
   * @api public
   */

  WS.prototype.name = 'websocket';

  /**
   * Initializes a new `WebSocket` connection with the Socket.IO server. We attach
   * all the appropriate listeners to handle the responses from the server.
   *
   * @returns {Transport}
   * @api public
   */

  WS.prototype.open = function () {
    var query = io.util.query(this.socket.options.query)
      , self = this
      , Socket


    if (!Socket) {
      Socket = global.MozWebSocket || global.WebSocket;
    }

    this.websocket = new Socket(this.prepareUrl() + query);

    this.websocket.onopen = function () {
      self.onOpen();
      self.socket.setBuffer(false);
    };
    this.websocket.onmessage = function (ev) {
      self.onData(ev.data);
    };
    this.websocket.onclose = function () {
      self.onClose();
      self.socket.setBuffer(true);
    };
    this.websocket.onerror = function (e) {
      self.onError(e);
    };

    return this;
  };

  /**
   * Send a message to the Socket.IO server. The message will automatically be
   * encoded in the correct message format.
   *
   * @returns {Transport}
   * @api public
   */

  // Do to a bug in the current IDevices browser, we need to wrap the send in a 
  // setTimeout, when they resume from sleeping the browser will crash if 
  // we don't allow the browser time to detect the socket has been closed
  if (io.util.ua.iDevice) {
    WS.prototype.send = function (data) {
      var self = this;
      setTimeout(function() {
         self.websocket.send(data);
      },0);
      return this;
    };
  } else {
    WS.prototype.send = function (data) {
      this.websocket.send(data);
      return this;
    };
  }

  /**
   * Payload
   *
   * @api private
   */

  WS.prototype.payload = function (arr) {
    for (var i = 0, l = arr.length; i < l; i++) {
      this.packet(arr[i]);
    }
    return this;
  };

  /**
   * Disconnect the established `WebSocket` connection.
   *
   * @returns {Transport}
   * @api public
   */

  WS.prototype.close = function () {
    this.websocket.close();
    return this;
  };

  /**
   * Handle the errors that `WebSocket` might be giving when we
   * are attempting to connect or send messages.
   *
   * @param {Error} e The error.
   * @api private
   */

  WS.prototype.onError = function (e) {
    this.socket.onError(e);
  };

  /**
   * Returns the appropriate scheme for the URI generation.
   *
   * @api private
   */
  WS.prototype.scheme = function () {
    return this.socket.options.secure ? 'wss' : 'ws';
  };

  /**
   * Checks if the browser has support for native `WebSockets` and that
   * it's not the polyfill created for the FlashSocket transport.
   *
   * @return {Boolean}
   * @api public
   */

  WS.check = function () {
    return ('WebSocket' in global && !('__addTask' in WebSocket))
          || 'MozWebSocket' in global;
  };

  /**
   * Check if the `WebSocket` transport support cross domain communications.
   *
   * @returns {Boolean}
   * @api public
   */

  WS.xdomainCheck = function () {
    return true;
  };

  /**
   * Add the transport to your public io.transports array.
   *
   * @api private
   */

  io.transports.push('websocket');

})(
    'undefined' != typeof io ? io.Transport : module.exports
  , 'undefined' != typeof io ? io : module.parent.exports
  , this
);

/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

(function (exports, io) {

  /**
   * Expose constructor.
   */

  exports.flashsocket = Flashsocket;

  /**
   * The FlashSocket transport. This is a API wrapper for the HTML5 WebSocket
   * specification. It uses a .swf file to communicate with the server. If you want
   * to serve the .swf file from a other server than where the Socket.IO script is
   * coming from you need to use the insecure version of the .swf. More information
   * about this can be found on the github page.
   *
   * @constructor
   * @extends {io.Transport.websocket}
   * @api public
   */

  function Flashsocket () {
    io.Transport.websocket.apply(this, arguments);
  };

  /**
   * Inherits from Transport.
   */

  io.util.inherit(Flashsocket, io.Transport.websocket);

  /**
   * Transport name
   *
   * @api public
   */

  Flashsocket.prototype.name = 'flashsocket';

  /**
   * Disconnect the established `FlashSocket` connection. This is done by adding a 
   * new task to the FlashSocket. The rest will be handled off by the `WebSocket` 
   * transport.
   *
   * @returns {Transport}
   * @api public
   */

  Flashsocket.prototype.open = function () {
    var self = this
      , args = arguments;

    WebSocket.__addTask(function () {
      io.Transport.websocket.prototype.open.apply(self, args);
    });
    return this;
  };
  
  /**
   * Sends a message to the Socket.IO server. This is done by adding a new
   * task to the FlashSocket. The rest will be handled off by the `WebSocket` 
   * transport.
   *
   * @returns {Transport}
   * @api public
   */

  Flashsocket.prototype.send = function () {
    var self = this, args = arguments;
    WebSocket.__addTask(function () {
      io.Transport.websocket.prototype.send.apply(self, args);
    });
    return this;
  };

  /**
   * Disconnects the established `FlashSocket` connection.
   *
   * @returns {Transport}
   * @api public
   */

  Flashsocket.prototype.close = function () {
    WebSocket.__tasks.length = 0;
    io.Transport.websocket.prototype.close.call(this);
    return this;
  };

  /**
   * The WebSocket fall back needs to append the flash container to the body
   * element, so we need to make sure we have access to it. Or defer the call
   * until we are sure there is a body element.
   *
   * @param {Socket} socket The socket instance that needs a transport
   * @param {Function} fn The callback
   * @api private
   */

  Flashsocket.prototype.ready = function (socket, fn) {
    function init () {
      var options = socket.options
        , port = options['flash policy port']
        , path = [
              'http' + (options.secure ? 's' : '') + ':/'
            , options.host + ':' + options.port
            , options.resource
            , 'static/flashsocket'
            , 'WebSocketMain' + (socket.isXDomain() ? 'Insecure' : '') + '.swf'
          ];

      // Only start downloading the swf file when the checked that this browser
      // actually supports it
      if (!Flashsocket.loaded) {
        if (typeof WEB_SOCKET_SWF_LOCATION === 'undefined') {
          // Set the correct file based on the XDomain settings
          WEB_SOCKET_SWF_LOCATION = path.join('/');
        }

        if (port !== 843) {
          WebSocket.loadFlashPolicyFile('xmlsocket://' + options.host + ':' + port);
        }

        WebSocket.__initialize();
        Flashsocket.loaded = true;
      }

      fn.call(self);
    }

    var self = this;
    if (document.body) return init();

    io.util.load(init);
  };

  /**
   * Check if the FlashSocket transport is supported as it requires that the Adobe
   * Flash Player plug-in version `10.0.0` or greater is installed. And also check if
   * the polyfill is correctly loaded.
   *
   * @returns {Boolean}
   * @api public
   */

  Flashsocket.check = function () {
    if (
        typeof WebSocket == 'undefined'
      || !('__initialize' in WebSocket) || !swfobject
    ) return false;

    return swfobject.getFlashPlayerVersion().major >= 10;
  };

  /**
   * Check if the FlashSocket transport can be used as cross domain / cross origin 
   * transport. Because we can't see which type (secure or insecure) of .swf is used
   * we will just return true.
   *
   * @returns {Boolean}
   * @api public
   */

  Flashsocket.xdomainCheck = function () {
    return true;
  };

  /**
   * Disable AUTO_INITIALIZATION
   */

  if (typeof window != 'undefined') {
    WEB_SOCKET_DISABLE_AUTO_INITIALIZATION = true;
  }

  /**
   * Add the transport to your public io.transports array.
   *
   * @api private
   */

  io.transports.push('flashsocket');
})(
    'undefined' != typeof io ? io.Transport : module.exports
  , 'undefined' != typeof io ? io : module.parent.exports
);
/*	SWFObject v2.2 <http://code.google.com/p/swfobject/> 
	is released under the MIT License <http://www.opensource.org/licenses/mit-license.php> 
*/
if ('undefined' != typeof window) {
var swfobject=function(){var D="undefined",r="object",S="Shockwave Flash",W="ShockwaveFlash.ShockwaveFlash",q="application/x-shockwave-flash",R="SWFObjectExprInst",x="onreadystatechange",O=window,j=document,t=navigator,T=false,U=[h],o=[],N=[],I=[],l,Q,E,B,J=false,a=false,n,G,m=true,M=function(){var aa=typeof j.getElementById!=D&&typeof j.getElementsByTagName!=D&&typeof j.createElement!=D,ah=t.userAgent.toLowerCase(),Y=t.platform.toLowerCase(),ae=Y?/win/.test(Y):/win/.test(ah),ac=Y?/mac/.test(Y):/mac/.test(ah),af=/webkit/.test(ah)?parseFloat(ah.replace(/^.*webkit\/(\d+(\.\d+)?).*$/,"$1")):false,X=!+"\v1",ag=[0,0,0],ab=null;if(typeof t.plugins!=D&&typeof t.plugins[S]==r){ab=t.plugins[S].description;if(ab&&!(typeof t.mimeTypes!=D&&t.mimeTypes[q]&&!t.mimeTypes[q].enabledPlugin)){T=true;X=false;ab=ab.replace(/^.*\s+(\S+\s+\S+$)/,"$1");ag[0]=parseInt(ab.replace(/^(.*)\..*$/,"$1"),10);ag[1]=parseInt(ab.replace(/^.*\.(.*)\s.*$/,"$1"),10);ag[2]=/[a-zA-Z]/.test(ab)?parseInt(ab.replace(/^.*[a-zA-Z]+(.*)$/,"$1"),10):0}}else{if(typeof O[(['Active'].concat('Object').join('X'))]!=D){try{var ad=new window[(['Active'].concat('Object').join('X'))](W);if(ad){ab=ad.GetVariable("$version");if(ab){X=true;ab=ab.split(" ")[1].split(",");ag=[parseInt(ab[0],10),parseInt(ab[1],10),parseInt(ab[2],10)]}}}catch(Z){}}}return{w3:aa,pv:ag,wk:af,ie:X,win:ae,mac:ac}}(),k=function(){if(!M.w3){return}if((typeof j.readyState!=D&&j.readyState=="complete")||(typeof j.readyState==D&&(j.getElementsByTagName("body")[0]||j.body))){f()}if(!J){if(typeof j.addEventListener!=D){j.addEventListener("DOMContentLoaded",f,false)}if(M.ie&&M.win){j.attachEvent(x,function(){if(j.readyState=="complete"){j.detachEvent(x,arguments.callee);f()}});if(O==top){(function(){if(J){return}try{j.documentElement.doScroll("left")}catch(X){setTimeout(arguments.callee,0);return}f()})()}}if(M.wk){(function(){if(J){return}if(!/loaded|complete/.test(j.readyState)){setTimeout(arguments.callee,0);return}f()})()}s(f)}}();function f(){if(J){return}try{var Z=j.getElementsByTagName("body")[0].appendChild(C("span"));Z.parentNode.removeChild(Z)}catch(aa){return}J=true;var X=U.length;for(var Y=0;Y<X;Y++){U[Y]()}}function K(X){if(J){X()}else{U[U.length]=X}}function s(Y){if(typeof O.addEventListener!=D){O.addEventListener("load",Y,false)}else{if(typeof j.addEventListener!=D){j.addEventListener("load",Y,false)}else{if(typeof O.attachEvent!=D){i(O,"onload",Y)}else{if(typeof O.onload=="function"){var X=O.onload;O.onload=function(){X();Y()}}else{O.onload=Y}}}}}function h(){if(T){V()}else{H()}}function V(){var X=j.getElementsByTagName("body")[0];var aa=C(r);aa.setAttribute("type",q);var Z=X.appendChild(aa);if(Z){var Y=0;(function(){if(typeof Z.GetVariable!=D){var ab=Z.GetVariable("$version");if(ab){ab=ab.split(" ")[1].split(",");M.pv=[parseInt(ab[0],10),parseInt(ab[1],10),parseInt(ab[2],10)]}}else{if(Y<10){Y++;setTimeout(arguments.callee,10);return}}X.removeChild(aa);Z=null;H()})()}else{H()}}function H(){var ag=o.length;if(ag>0){for(var af=0;af<ag;af++){var Y=o[af].id;var ab=o[af].callbackFn;var aa={success:false,id:Y};if(M.pv[0]>0){var ae=c(Y);if(ae){if(F(o[af].swfVersion)&&!(M.wk&&M.wk<312)){w(Y,true);if(ab){aa.success=true;aa.ref=z(Y);ab(aa)}}else{if(o[af].expressInstall&&A()){var ai={};ai.data=o[af].expressInstall;ai.width=ae.getAttribute("width")||"0";ai.height=ae.getAttribute("height")||"0";if(ae.getAttribute("class")){ai.styleclass=ae.getAttribute("class")}if(ae.getAttribute("align")){ai.align=ae.getAttribute("align")}var ah={};var X=ae.getElementsByTagName("param");var ac=X.length;for(var ad=0;ad<ac;ad++){if(X[ad].getAttribute("name").toLowerCase()!="movie"){ah[X[ad].getAttribute("name")]=X[ad].getAttribute("value")}}P(ai,ah,Y,ab)}else{p(ae);if(ab){ab(aa)}}}}}else{w(Y,true);if(ab){var Z=z(Y);if(Z&&typeof Z.SetVariable!=D){aa.success=true;aa.ref=Z}ab(aa)}}}}}function z(aa){var X=null;var Y=c(aa);if(Y&&Y.nodeName=="OBJECT"){if(typeof Y.SetVariable!=D){X=Y}else{var Z=Y.getElementsByTagName(r)[0];if(Z){X=Z}}}return X}function A(){return !a&&F("6.0.65")&&(M.win||M.mac)&&!(M.wk&&M.wk<312)}function P(aa,ab,X,Z){a=true;E=Z||null;B={success:false,id:X};var ae=c(X);if(ae){if(ae.nodeName=="OBJECT"){l=g(ae);Q=null}else{l=ae;Q=X}aa.id=R;if(typeof aa.width==D||(!/%$/.test(aa.width)&&parseInt(aa.width,10)<310)){aa.width="310"}if(typeof aa.height==D||(!/%$/.test(aa.height)&&parseInt(aa.height,10)<137)){aa.height="137"}j.title=j.title.slice(0,47)+" - Flash Player Installation";var ad=M.ie&&M.win?(['Active'].concat('').join('X')):"PlugIn",ac="MMredirectURL="+O.location.toString().replace(/&/g,"%26")+"&MMplayerType="+ad+"&MMdoctitle="+j.title;if(typeof ab.flashvars!=D){ab.flashvars+="&"+ac}else{ab.flashvars=ac}if(M.ie&&M.win&&ae.readyState!=4){var Y=C("div");X+="SWFObjectNew";Y.setAttribute("id",X);ae.parentNode.insertBefore(Y,ae);ae.style.display="none";(function(){if(ae.readyState==4){ae.parentNode.removeChild(ae)}else{setTimeout(arguments.callee,10)}})()}u(aa,ab,X)}}function p(Y){if(M.ie&&M.win&&Y.readyState!=4){var X=C("div");Y.parentNode.insertBefore(X,Y);X.parentNode.replaceChild(g(Y),X);Y.style.display="none";(function(){if(Y.readyState==4){Y.parentNode.removeChild(Y)}else{setTimeout(arguments.callee,10)}})()}else{Y.parentNode.replaceChild(g(Y),Y)}}function g(ab){var aa=C("div");if(M.win&&M.ie){aa.innerHTML=ab.innerHTML}else{var Y=ab.getElementsByTagName(r)[0];if(Y){var ad=Y.childNodes;if(ad){var X=ad.length;for(var Z=0;Z<X;Z++){if(!(ad[Z].nodeType==1&&ad[Z].nodeName=="PARAM")&&!(ad[Z].nodeType==8)){aa.appendChild(ad[Z].cloneNode(true))}}}}}return aa}function u(ai,ag,Y){var X,aa=c(Y);if(M.wk&&M.wk<312){return X}if(aa){if(typeof ai.id==D){ai.id=Y}if(M.ie&&M.win){var ah="";for(var ae in ai){if(ai[ae]!=Object.prototype[ae]){if(ae.toLowerCase()=="data"){ag.movie=ai[ae]}else{if(ae.toLowerCase()=="styleclass"){ah+=' class="'+ai[ae]+'"'}else{if(ae.toLowerCase()!="classid"){ah+=" "+ae+'="'+ai[ae]+'"'}}}}}var af="";for(var ad in ag){if(ag[ad]!=Object.prototype[ad]){af+='<param name="'+ad+'" value="'+ag[ad]+'" />'}}aa.outerHTML='<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000"'+ah+">"+af+"</object>";N[N.length]=ai.id;X=c(ai.id)}else{var Z=C(r);Z.setAttribute("type",q);for(var ac in ai){if(ai[ac]!=Object.prototype[ac]){if(ac.toLowerCase()=="styleclass"){Z.setAttribute("class",ai[ac])}else{if(ac.toLowerCase()!="classid"){Z.setAttribute(ac,ai[ac])}}}}for(var ab in ag){if(ag[ab]!=Object.prototype[ab]&&ab.toLowerCase()!="movie"){e(Z,ab,ag[ab])}}aa.parentNode.replaceChild(Z,aa);X=Z}}return X}function e(Z,X,Y){var aa=C("param");aa.setAttribute("name",X);aa.setAttribute("value",Y);Z.appendChild(aa)}function y(Y){var X=c(Y);if(X&&X.nodeName=="OBJECT"){if(M.ie&&M.win){X.style.display="none";(function(){if(X.readyState==4){b(Y)}else{setTimeout(arguments.callee,10)}})()}else{X.parentNode.removeChild(X)}}}function b(Z){var Y=c(Z);if(Y){for(var X in Y){if(typeof Y[X]=="function"){Y[X]=null}}Y.parentNode.removeChild(Y)}}function c(Z){var X=null;try{X=j.getElementById(Z)}catch(Y){}return X}function C(X){return j.createElement(X)}function i(Z,X,Y){Z.attachEvent(X,Y);I[I.length]=[Z,X,Y]}function F(Z){var Y=M.pv,X=Z.split(".");X[0]=parseInt(X[0],10);X[1]=parseInt(X[1],10)||0;X[2]=parseInt(X[2],10)||0;return(Y[0]>X[0]||(Y[0]==X[0]&&Y[1]>X[1])||(Y[0]==X[0]&&Y[1]==X[1]&&Y[2]>=X[2]))?true:false}function v(ac,Y,ad,ab){if(M.ie&&M.mac){return}var aa=j.getElementsByTagName("head")[0];if(!aa){return}var X=(ad&&typeof ad=="string")?ad:"screen";if(ab){n=null;G=null}if(!n||G!=X){var Z=C("style");Z.setAttribute("type","text/css");Z.setAttribute("media",X);n=aa.appendChild(Z);if(M.ie&&M.win&&typeof j.styleSheets!=D&&j.styleSheets.length>0){n=j.styleSheets[j.styleSheets.length-1]}G=X}if(M.ie&&M.win){if(n&&typeof n.addRule==r){n.addRule(ac,Y)}}else{if(n&&typeof j.createTextNode!=D){n.appendChild(j.createTextNode(ac+" {"+Y+"}"))}}}function w(Z,X){if(!m){return}var Y=X?"visible":"hidden";if(J&&c(Z)){c(Z).style.visibility=Y}else{v("#"+Z,"visibility:"+Y)}}function L(Y){var Z=/[\\\"<>\.;]/;var X=Z.exec(Y)!=null;return X&&typeof encodeURIComponent!=D?encodeURIComponent(Y):Y}var d=function(){if(M.ie&&M.win){window.attachEvent("onunload",function(){var ac=I.length;for(var ab=0;ab<ac;ab++){I[ab][0].detachEvent(I[ab][1],I[ab][2])}var Z=N.length;for(var aa=0;aa<Z;aa++){y(N[aa])}for(var Y in M){M[Y]=null}M=null;for(var X in swfobject){swfobject[X]=null}swfobject=null})}}();return{registerObject:function(ab,X,aa,Z){if(M.w3&&ab&&X){var Y={};Y.id=ab;Y.swfVersion=X;Y.expressInstall=aa;Y.callbackFn=Z;o[o.length]=Y;w(ab,false)}else{if(Z){Z({success:false,id:ab})}}},getObjectById:function(X){if(M.w3){return z(X)}},embedSWF:function(ab,ah,ae,ag,Y,aa,Z,ad,af,ac){var X={success:false,id:ah};if(M.w3&&!(M.wk&&M.wk<312)&&ab&&ah&&ae&&ag&&Y){w(ah,false);K(function(){ae+="";ag+="";var aj={};if(af&&typeof af===r){for(var al in af){aj[al]=af[al]}}aj.data=ab;aj.width=ae;aj.height=ag;var am={};if(ad&&typeof ad===r){for(var ak in ad){am[ak]=ad[ak]}}if(Z&&typeof Z===r){for(var ai in Z){if(typeof am.flashvars!=D){am.flashvars+="&"+ai+"="+Z[ai]}else{am.flashvars=ai+"="+Z[ai]}}}if(F(Y)){var an=u(aj,am,ah);if(aj.id==ah){w(ah,true)}X.success=true;X.ref=an}else{if(aa&&A()){aj.data=aa;P(aj,am,ah,ac);return}else{w(ah,true)}}if(ac){ac(X)}})}else{if(ac){ac(X)}}},switchOffAutoHideShow:function(){m=false},ua:M,getFlashPlayerVersion:function(){return{major:M.pv[0],minor:M.pv[1],release:M.pv[2]}},hasFlashPlayerVersion:F,createSWF:function(Z,Y,X){if(M.w3){return u(Z,Y,X)}else{return undefined}},showExpressInstall:function(Z,aa,X,Y){if(M.w3&&A()){P(Z,aa,X,Y)}},removeSWF:function(X){if(M.w3){y(X)}},createCSS:function(aa,Z,Y,X){if(M.w3){v(aa,Z,Y,X)}},addDomLoadEvent:K,addLoadEvent:s,getQueryParamValue:function(aa){var Z=j.location.search||j.location.hash;if(Z){if(/\?/.test(Z)){Z=Z.split("?")[1]}if(aa==null){return L(Z)}var Y=Z.split("&");for(var X=0;X<Y.length;X++){if(Y[X].substring(0,Y[X].indexOf("="))==aa){return L(Y[X].substring((Y[X].indexOf("=")+1)))}}}return""},expressInstallCallback:function(){if(a){var X=c(R);if(X&&l){X.parentNode.replaceChild(l,X);if(Q){w(Q,true);if(M.ie&&M.win){l.style.display="block"}}if(E){E(B)}}a=false}}}}();
}
// Copyright: Hiroshi Ichikawa <http://gimite.net/en/>
// License: New BSD License
// Reference: http://dev.w3.org/html5/websockets/
// Reference: http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol

(function() {
  
  if ('undefined' == typeof window || window.WebSocket) return;

  var console = window.console;
  if (!console || !console.log || !console.error) {
    console = {log: function(){ }, error: function(){ }};
  }
  
  if (!swfobject.hasFlashPlayerVersion("10.0.0")) {
    console.error("Flash Player >= 10.0.0 is required.");
    return;
  }
  if (location.protocol == "file:") {
    console.error(
      "WARNING: web-socket-js doesn't work in file:///... URL " +
      "unless you set Flash Security Settings properly. " +
      "Open the page via Web server i.e. http://...");
  }

  /**
   * This class represents a faux web socket.
   * @param {string} url
   * @param {array or string} protocols
   * @param {string} proxyHost
   * @param {int} proxyPort
   * @param {string} headers
   */
  WebSocket = function(url, protocols, proxyHost, proxyPort, headers) {
    var self = this;
    self.__id = WebSocket.__nextId++;
    WebSocket.__instances[self.__id] = self;
    self.readyState = WebSocket.CONNECTING;
    self.bufferedAmount = 0;
    self.__events = {};
    if (!protocols) {
      protocols = [];
    } else if (typeof protocols == "string") {
      protocols = [protocols];
    }
    // Uses setTimeout() to make sure __createFlash() runs after the caller sets ws.onopen etc.
    // Otherwise, when onopen fires immediately, onopen is called before it is set.
    setTimeout(function() {
      WebSocket.__addTask(function() {
        WebSocket.__flash.create(
            self.__id, url, protocols, proxyHost || null, proxyPort || 0, headers || null);
      });
    }, 0);
  };

  /**
   * Send data to the web socket.
   * @param {string} data  The data to send to the socket.
   * @return {boolean}  True for success, false for failure.
   */
  WebSocket.prototype.send = function(data) {
    if (this.readyState == WebSocket.CONNECTING) {
      throw "INVALID_STATE_ERR: Web Socket connection has not been established";
    }
    // We use encodeURIComponent() here, because FABridge doesn't work if
    // the argument includes some characters. We don't use escape() here
    // because of this:
    // https://developer.mozilla.org/en/Core_JavaScript_1.5_Guide/Functions#escape_and_unescape_Functions
    // But it looks decodeURIComponent(encodeURIComponent(s)) doesn't
    // preserve all Unicode characters either e.g. "\uffff" in Firefox.
    // Note by wtritch: Hopefully this will not be necessary using ExternalInterface.  Will require
    // additional testing.
    var result = WebSocket.__flash.send(this.__id, encodeURIComponent(data));
    if (result < 0) { // success
      return true;
    } else {
      this.bufferedAmount += result;
      return false;
    }
  };

  /**
   * Close this web socket gracefully.
   */
  WebSocket.prototype.close = function() {
    if (this.readyState == WebSocket.CLOSED || this.readyState == WebSocket.CLOSING) {
      return;
    }
    this.readyState = WebSocket.CLOSING;
    WebSocket.__flash.close(this.__id);
  };

  /**
   * Implementation of {@link <a href="http://www.w3.org/TR/DOM-Level-2-Events/events.html#Events-registration">DOM 2 EventTarget Interface</a>}
   *
   * @param {string} type
   * @param {function} listener
   * @param {boolean} useCapture
   * @return void
   */
  WebSocket.prototype.addEventListener = function(type, listener, useCapture) {
    if (!(type in this.__events)) {
      this.__events[type] = [];
    }
    this.__events[type].push(listener);
  };

  /**
   * Implementation of {@link <a href="http://www.w3.org/TR/DOM-Level-2-Events/events.html#Events-registration">DOM 2 EventTarget Interface</a>}
   *
   * @param {string} type
   * @param {function} listener
   * @param {boolean} useCapture
   * @return void
   */
  WebSocket.prototype.removeEventListener = function(type, listener, useCapture) {
    if (!(type in this.__events)) return;
    var events = this.__events[type];
    for (var i = events.length - 1; i >= 0; --i) {
      if (events[i] === listener) {
        events.splice(i, 1);
        break;
      }
    }
  };

  /**
   * Implementation of {@link <a href="http://www.w3.org/TR/DOM-Level-2-Events/events.html#Events-registration">DOM 2 EventTarget Interface</a>}
   *
   * @param {Event} event
   * @return void
   */
  WebSocket.prototype.dispatchEvent = function(event) {
    var events = this.__events[event.type] || [];
    for (var i = 0; i < events.length; ++i) {
      events[i](event);
    }
    var handler = this["on" + event.type];
    if (handler) handler(event);
  };

  /**
   * Handles an event from Flash.
   * @param {Object} flashEvent
   */
  WebSocket.prototype.__handleEvent = function(flashEvent) {
    if ("readyState" in flashEvent) {
      this.readyState = flashEvent.readyState;
    }
    if ("protocol" in flashEvent) {
      this.protocol = flashEvent.protocol;
    }
    
    var jsEvent;
    if (flashEvent.type == "open" || flashEvent.type == "error") {
      jsEvent = this.__createSimpleEvent(flashEvent.type);
    } else if (flashEvent.type == "close") {
      // TODO implement jsEvent.wasClean
      jsEvent = this.__createSimpleEvent("close");
    } else if (flashEvent.type == "message") {
      var data = decodeURIComponent(flashEvent.message);
      jsEvent = this.__createMessageEvent("message", data);
    } else {
      throw "unknown event type: " + flashEvent.type;
    }
    
    this.dispatchEvent(jsEvent);
  };
  
  WebSocket.prototype.__createSimpleEvent = function(type) {
    if (document.createEvent && window.Event) {
      var event = document.createEvent("Event");
      event.initEvent(type, false, false);
      return event;
    } else {
      return {type: type, bubbles: false, cancelable: false};
    }
  };
  
  WebSocket.prototype.__createMessageEvent = function(type, data) {
    if (document.createEvent && window.MessageEvent && !window.opera) {
      var event = document.createEvent("MessageEvent");
      event.initMessageEvent("message", false, false, data, null, null, window, null);
      return event;
    } else {
      // IE and Opera, the latter one truncates the data parameter after any 0x00 bytes.
      return {type: type, data: data, bubbles: false, cancelable: false};
    }
  };
  
  /**
   * Define the WebSocket readyState enumeration.
   */
  WebSocket.CONNECTING = 0;
  WebSocket.OPEN = 1;
  WebSocket.CLOSING = 2;
  WebSocket.CLOSED = 3;

  WebSocket.__flash = null;
  WebSocket.__instances = {};
  WebSocket.__tasks = [];
  WebSocket.__nextId = 0;
  
  /**
   * Load a new flash security policy file.
   * @param {string} url
   */
  WebSocket.loadFlashPolicyFile = function(url){
    WebSocket.__addTask(function() {
      WebSocket.__flash.loadManualPolicyFile(url);
    });
  };

  /**
   * Loads WebSocketMain.swf and creates WebSocketMain object in Flash.
   */
  WebSocket.__initialize = function() {
    if (WebSocket.__flash) return;
    
    if (WebSocket.__swfLocation) {
      // For backword compatibility.
      window.WEB_SOCKET_SWF_LOCATION = WebSocket.__swfLocation;
    }
    if (!window.WEB_SOCKET_SWF_LOCATION) {
      console.error("[WebSocket] set WEB_SOCKET_SWF_LOCATION to location of WebSocketMain.swf");
      return;
    }
    var container = document.createElement("div");
    container.id = "webSocketContainer";
    // Hides Flash box. We cannot use display: none or visibility: hidden because it prevents
    // Flash from loading at least in IE. So we move it out of the screen at (-100, -100).
    // But this even doesn't work with Flash Lite (e.g. in Droid Incredible). So with Flash
    // Lite, we put it at (0, 0). This shows 1x1 box visible at left-top corner but this is
    // the best we can do as far as we know now.
    container.style.position = "absolute";
    if (WebSocket.__isFlashLite()) {
      container.style.left = "0px";
      container.style.top = "0px";
    } else {
      container.style.left = "-100px";
      container.style.top = "-100px";
    }
    var holder = document.createElement("div");
    holder.id = "webSocketFlash";
    container.appendChild(holder);
    document.body.appendChild(container);
    // See this article for hasPriority:
    // http://help.adobe.com/en_US/as3/mobile/WS4bebcd66a74275c36cfb8137124318eebc6-7ffd.html
    swfobject.embedSWF(
      WEB_SOCKET_SWF_LOCATION,
      "webSocketFlash",
      "1" /* width */,
      "1" /* height */,
      "10.0.0" /* SWF version */,
      null,
      null,
      {hasPriority: true, swliveconnect : true, allowScriptAccess: "always"},
      null,
      function(e) {
        if (!e.success) {
          console.error("[WebSocket] swfobject.embedSWF failed");
        }
      });
  };
  
  /**
   * Called by Flash to notify JS that it's fully loaded and ready
   * for communication.
   */
  WebSocket.__onFlashInitialized = function() {
    // We need to set a timeout here to avoid round-trip calls
    // to flash during the initialization process.
    setTimeout(function() {
      WebSocket.__flash = document.getElementById("webSocketFlash");
      WebSocket.__flash.setCallerUrl(location.href);
      WebSocket.__flash.setDebug(!!window.WEB_SOCKET_DEBUG);
      for (var i = 0; i < WebSocket.__tasks.length; ++i) {
        WebSocket.__tasks[i]();
      }
      WebSocket.__tasks = [];
    }, 0);
  };
  
  /**
   * Called by Flash to notify WebSockets events are fired.
   */
  WebSocket.__onFlashEvent = function() {
    setTimeout(function() {
      try {
        // Gets events using receiveEvents() instead of getting it from event object
        // of Flash event. This is to make sure to keep message order.
        // It seems sometimes Flash events don't arrive in the same order as they are sent.
        var events = WebSocket.__flash.receiveEvents();
        for (var i = 0; i < events.length; ++i) {
          WebSocket.__instances[events[i].webSocketId].__handleEvent(events[i]);
        }
      } catch (e) {
        console.error(e);
      }
    }, 0);
    return true;
  };
  
  // Called by Flash.
  WebSocket.__log = function(message) {
    console.log(decodeURIComponent(message));
  };
  
  // Called by Flash.
  WebSocket.__error = function(message) {
    console.error(decodeURIComponent(message));
  };
  
  WebSocket.__addTask = function(task) {
    if (WebSocket.__flash) {
      task();
    } else {
      WebSocket.__tasks.push(task);
    }
  };
  
  /**
   * Test if the browser is running flash lite.
   * @return {boolean} True if flash lite is running, false otherwise.
   */
  WebSocket.__isFlashLite = function() {
    if (!window.navigator || !window.navigator.mimeTypes) {
      return false;
    }
    var mimeType = window.navigator.mimeTypes["application/x-shockwave-flash"];
    if (!mimeType || !mimeType.enabledPlugin || !mimeType.enabledPlugin.filename) {
      return false;
    }
    return mimeType.enabledPlugin.filename.match(/flashlite/i) ? true : false;
  };
  
  if (!window.WEB_SOCKET_DISABLE_AUTO_INITIALIZATION) {
    if (window.addEventListener) {
      window.addEventListener("load", function(){
        WebSocket.__initialize();
      }, false);
    } else {
      window.attachEvent("onload", function(){
        WebSocket.__initialize();
      });
    }
  }
  
})();

/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

(function (exports, io, global) {

  /**
   * Expose constructor.
   *
   * @api public
   */

  exports.XHR = XHR;

  /**
   * XHR constructor
   *
   * @costructor
   * @api public
   */

  function XHR (socket) {
    if (!socket) return;

    io.Transport.apply(this, arguments);
    this.sendBuffer = [];
  };

  /**
   * Inherits from Transport.
   */

  io.util.inherit(XHR, io.Transport);

  /**
   * Establish a connection
   *
   * @returns {Transport}
   * @api public
   */

  XHR.prototype.open = function () {
    this.socket.setBuffer(false);
    this.onOpen();
    this.get();

    // we need to make sure the request succeeds since we have no indication
    // whether the request opened or not until it succeeded.
    this.setCloseTimeout();

    return this;
  };

  /**
   * Check if we need to send data to the Socket.IO server, if we have data in our
   * buffer we encode it and forward it to the `post` method.
   *
   * @api private
   */

  XHR.prototype.payload = function (payload) {
    var msgs = [];

    for (var i = 0, l = payload.length; i < l; i++) {
      msgs.push(io.parser.encodePacket(payload[i]));
    }

    this.send(io.parser.encodePayload(msgs));
  };

  /**
   * Send data to the Socket.IO server.
   *
   * @param data The message
   * @returns {Transport}
   * @api public
   */

  XHR.prototype.send = function (data) {
    this.post(data);
    return this;
  };

  /**
   * Posts a encoded message to the Socket.IO server.
   *
   * @param {String} data A encoded message.
   * @api private
   */

  function empty () { };

  XHR.prototype.post = function (data) {
    var self = this;
    this.socket.setBuffer(true);

    function stateChange () {
      if (this.readyState == 4) {
        this.onreadystatechange = empty;
        self.posting = false;

        if (this.status == 200){
          self.socket.setBuffer(false);
        } else {
          self.onClose();
        }
      }
    }

    function onload () {
      this.onload = empty;
      self.socket.setBuffer(false);
    };

    this.sendXHR = this.request('POST');

    if (global.XDomainRequest && this.sendXHR instanceof XDomainRequest) {
      this.sendXHR.onload = this.sendXHR.onerror = onload;
    } else {
      this.sendXHR.onreadystatechange = stateChange;
    }

    this.sendXHR.send(data);
  };

  /**
   * Disconnects the established `XHR` connection.
   *
   * @returns {Transport}
   * @api public
   */

  XHR.prototype.close = function () {
    this.onClose();
    return this;
  };

  /**
   * Generates a configured XHR request
   *
   * @param {String} url The url that needs to be requested.
   * @param {String} method The method the request should use.
   * @returns {XMLHttpRequest}
   * @api private
   */

  XHR.prototype.request = function (method) {
    var req = io.util.request(this.socket.isXDomain())
      , query = io.util.query(this.socket.options.query, 't=' + +new Date);

    req.open(method || 'GET', this.prepareUrl() + query, true);

    if (method == 'POST') {
      try {
        if (req.setRequestHeader) {
          req.setRequestHeader('Content-type', 'text/plain;charset=UTF-8');
        } else {
          // XDomainRequest
          req.contentType = 'text/plain';
        }
      } catch (e) {}
    }

    return req;
  };

  /**
   * Returns the scheme to use for the transport URLs.
   *
   * @api private
   */

  XHR.prototype.scheme = function () {
    return this.socket.options.secure ? 'https' : 'http';
  };

  /**
   * Check if the XHR transports are supported
   *
   * @param {Boolean} xdomain Check if we support cross domain requests.
   * @returns {Boolean}
   * @api public
   */

  XHR.check = function (socket, xdomain) {
    try {
      var request = io.util.request(xdomain),
          usesXDomReq = (global.XDomainRequest && request instanceof XDomainRequest),
          socketProtocol = (socket && socket.options && socket.options.secure ? 'https:' : 'http:'),
          isXProtocol = (global.location && socketProtocol != global.location.protocol);
      if (request && !(usesXDomReq && isXProtocol)) {
        return true;
      }
    } catch(e) {}

    return false;
  };

  /**
   * Check if the XHR transport supports cross domain requests.
   *
   * @returns {Boolean}
   * @api public
   */

  XHR.xdomainCheck = function (socket) {
    return XHR.check(socket, true);
  };

})(
    'undefined' != typeof io ? io.Transport : module.exports
  , 'undefined' != typeof io ? io : module.parent.exports
  , this
);
/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

(function (exports, io) {

  /**
   * Expose constructor.
   */

  exports.htmlfile = HTMLFile;

  /**
   * The HTMLFile transport creates a `forever iframe` based transport
   * for Internet Explorer. Regular forever iframe implementations will 
   * continuously trigger the browsers buzy indicators. If the forever iframe
   * is created inside a `htmlfile` these indicators will not be trigged.
   *
   * @constructor
   * @extends {io.Transport.XHR}
   * @api public
   */

  function HTMLFile (socket) {
    io.Transport.XHR.apply(this, arguments);
  };

  /**
   * Inherits from XHR transport.
   */

  io.util.inherit(HTMLFile, io.Transport.XHR);

  /**
   * Transport name
   *
   * @api public
   */

  HTMLFile.prototype.name = 'htmlfile';

  /**
   * Creates a new Ac...eX `htmlfile` with a forever loading iframe
   * that can be used to listen to messages. Inside the generated
   * `htmlfile` a reference will be made to the HTMLFile transport.
   *
   * @api private
   */

  HTMLFile.prototype.get = function () {
    this.doc = new window[(['Active'].concat('Object').join('X'))]('htmlfile');
    this.doc.open();
    this.doc.write('<html></html>');
    this.doc.close();
    this.doc.parentWindow.s = this;

    var iframeC = this.doc.createElement('div');
    iframeC.className = 'socketio';

    this.doc.body.appendChild(iframeC);
    this.iframe = this.doc.createElement('iframe');

    iframeC.appendChild(this.iframe);

    var self = this
      , query = io.util.query(this.socket.options.query, 't='+ +new Date);

    this.iframe.src = this.prepareUrl() + query;

    io.util.on(window, 'unload', function () {
      self.destroy();
    });
  };

  /**
   * The Socket.IO server will write script tags inside the forever
   * iframe, this function will be used as callback for the incoming
   * information.
   *
   * @param {String} data The message
   * @param {document} doc Reference to the context
   * @api private
   */

  HTMLFile.prototype._ = function (data, doc) {
    // unescape all forward slashes. see GH-1251
    data = data.replace(/\\\//g, '/');
    this.onData(data);
    try {
      var script = doc.getElementsByTagName('script')[0];
      script.parentNode.removeChild(script);
    } catch (e) { }
  };

  /**
   * Destroy the established connection, iframe and `htmlfile`.
   * And calls the `CollectGarbage` function of Internet Explorer
   * to release the memory.
   *
   * @api private
   */

  HTMLFile.prototype.destroy = function () {
    if (this.iframe){
      try {
        this.iframe.src = 'about:blank';
      } catch(e){}

      this.doc = null;
      this.iframe.parentNode.removeChild(this.iframe);
      this.iframe = null;

      CollectGarbage();
    }
  };

  /**
   * Disconnects the established connection.
   *
   * @returns {Transport} Chaining.
   * @api public
   */

  HTMLFile.prototype.close = function () {
    this.destroy();
    return io.Transport.XHR.prototype.close.call(this);
  };

  /**
   * Checks if the browser supports this transport. The browser
   * must have an `Ac...eXObject` implementation.
   *
   * @return {Boolean}
   * @api public
   */

  HTMLFile.check = function (socket) {
    if (typeof window != "undefined" && (['Active'].concat('Object').join('X')) in window){
      try {
        var a = new window[(['Active'].concat('Object').join('X'))]('htmlfile');
        return a && io.Transport.XHR.check(socket);
      } catch(e){}
    }
    return false;
  };

  /**
   * Check if cross domain requests are supported.
   *
   * @returns {Boolean}
   * @api public
   */

  HTMLFile.xdomainCheck = function () {
    // we can probably do handling for sub-domains, we should
    // test that it's cross domain but a subdomain here
    return false;
  };

  /**
   * Add the transport to your public io.transports array.
   *
   * @api private
   */

  io.transports.push('htmlfile');

})(
    'undefined' != typeof io ? io.Transport : module.exports
  , 'undefined' != typeof io ? io : module.parent.exports
);

/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

(function (exports, io, global) {

  /**
   * Expose constructor.
   */

  exports['xhr-polling'] = XHRPolling;

  /**
   * The XHR-polling transport uses long polling XHR requests to create a
   * "persistent" connection with the server.
   *
   * @constructor
   * @api public
   */

  function XHRPolling () {
    io.Transport.XHR.apply(this, arguments);
  };

  /**
   * Inherits from XHR transport.
   */

  io.util.inherit(XHRPolling, io.Transport.XHR);

  /**
   * Merge the properties from XHR transport
   */

  io.util.merge(XHRPolling, io.Transport.XHR);

  /**
   * Transport name
   *
   * @api public
   */

  XHRPolling.prototype.name = 'xhr-polling';

  /**
   * Indicates whether heartbeats is enabled for this transport
   *
   * @api private
   */

  XHRPolling.prototype.heartbeats = function () {
    return false;
  };

  /** 
   * Establish a connection, for iPhone and Android this will be done once the page
   * is loaded.
   *
   * @returns {Transport} Chaining.
   * @api public
   */

  XHRPolling.prototype.open = function () {
    var self = this;

    io.Transport.XHR.prototype.open.call(self);
    return false;
  };

  /**
   * Starts a XHR request to wait for incoming messages.
   *
   * @api private
   */

  function empty () {};

  XHRPolling.prototype.get = function () {
    if (!this.isOpen) return;

    var self = this;

    function stateChange () {
      if (this.readyState == 4) {
        this.onreadystatechange = empty;

        if (this.status == 200) {
          self.onData(this.responseText);
          self.get();
        } else {
          self.onClose();
        }
      }
    };

    function onload () {
      this.onload = empty;
      this.onerror = empty;
      self.retryCounter = 1;
      self.onData(this.responseText);
      self.get();
    };

    function onerror () {
      self.retryCounter ++;
      if(!self.retryCounter || self.retryCounter > 3) {
        self.onClose();  
      } else {
        self.get();
      }
    };

    this.xhr = this.request();

    if (global.XDomainRequest && this.xhr instanceof XDomainRequest) {
      this.xhr.onload = onload;
      this.xhr.onerror = onerror;
    } else {
      this.xhr.onreadystatechange = stateChange;
    }

    this.xhr.send(null);
  };

  /**
   * Handle the unclean close behavior.
   *
   * @api private
   */

  XHRPolling.prototype.onClose = function () {
    io.Transport.XHR.prototype.onClose.call(this);

    if (this.xhr) {
      this.xhr.onreadystatechange = this.xhr.onload = this.xhr.onerror = empty;
      try {
        this.xhr.abort();
      } catch(e){}
      this.xhr = null;
    }
  };

  /**
   * Webkit based browsers show a infinit spinner when you start a XHR request
   * before the browsers onload event is called so we need to defer opening of
   * the transport until the onload event is called. Wrapping the cb in our
   * defer method solve this.
   *
   * @param {Socket} socket The socket instance that needs a transport
   * @param {Function} fn The callback
   * @api private
   */

  XHRPolling.prototype.ready = function (socket, fn) {
    var self = this;

    io.util.defer(function () {
      fn.call(self);
    });
  };

  /**
   * Add the transport to your public io.transports array.
   *
   * @api private
   */

  io.transports.push('xhr-polling');

})(
    'undefined' != typeof io ? io.Transport : module.exports
  , 'undefined' != typeof io ? io : module.parent.exports
  , this
);

/**
 * socket.io
 * Copyright(c) 2011 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

(function (exports, io, global) {
  /**
   * There is a way to hide the loading indicator in Firefox. If you create and
   * remove a iframe it will stop showing the current loading indicator.
   * Unfortunately we can't feature detect that and UA sniffing is evil.
   *
   * @api private
   */

  var indicator = global.document && "MozAppearance" in
    global.document.documentElement.style;

  /**
   * Expose constructor.
   */

  exports['jsonp-polling'] = JSONPPolling;

  /**
   * The JSONP transport creates an persistent connection by dynamically
   * inserting a script tag in the page. This script tag will receive the
   * information of the Socket.IO server. When new information is received
   * it creates a new script tag for the new data stream.
   *
   * @constructor
   * @extends {io.Transport.xhr-polling}
   * @api public
   */

  function JSONPPolling (socket) {
    io.Transport['xhr-polling'].apply(this, arguments);

    this.index = io.j.length;

    var self = this;

    io.j.push(function (msg) {
      self._(msg);
    });
  };

  /**
   * Inherits from XHR polling transport.
   */

  io.util.inherit(JSONPPolling, io.Transport['xhr-polling']);

  /**
   * Transport name
   *
   * @api public
   */

  JSONPPolling.prototype.name = 'jsonp-polling';

  /**
   * Posts a encoded message to the Socket.IO server using an iframe.
   * The iframe is used because script tags can create POST based requests.
   * The iframe is positioned outside of the view so the user does not
   * notice it's existence.
   *
   * @param {String} data A encoded message.
   * @api private
   */

  JSONPPolling.prototype.post = function (data) {
    var self = this
      , query = io.util.query(
             this.socket.options.query
          , 't='+ (+new Date) + '&i=' + this.index
        );

    if (!this.form) {
      var form = document.createElement('form')
        , area = document.createElement('textarea')
        , id = this.iframeId = 'socketio_iframe_' + this.index
        , iframe;

      form.className = 'socketio';
      form.style.position = 'absolute';
      form.style.top = '0px';
      form.style.left = '0px';
      form.style.display = 'none';
      form.target = id;
      form.method = 'POST';
      form.setAttribute('accept-charset', 'utf-8');
      area.name = 'd';
      form.appendChild(area);
      document.body.appendChild(form);

      this.form = form;
      this.area = area;
    }

    this.form.action = this.prepareUrl() + query;

    function complete () {
      initIframe();
      self.socket.setBuffer(false);
    };

    function initIframe () {
      if (self.iframe) {
        self.form.removeChild(self.iframe);
      }

      try {
        // ie6 dynamic iframes with target="" support (thanks Chris Lambacher)
        iframe = document.createElement('<iframe name="'+ self.iframeId +'">');
      } catch (e) {
        iframe = document.createElement('iframe');
        iframe.name = self.iframeId;
      }

      iframe.id = self.iframeId;

      self.form.appendChild(iframe);
      self.iframe = iframe;
    };

    initIframe();

    // we temporarily stringify until we figure out how to prevent
    // browsers from turning `\n` into `\r\n` in form inputs
    this.area.value = io.JSON.stringify(data);

    try {
      this.form.submit();
    } catch(e) {}

    if (this.iframe.attachEvent) {
      iframe.onreadystatechange = function () {
        if (self.iframe.readyState == 'complete') {
          complete();
        }
      };
    } else {
      this.iframe.onload = complete;
    }

    this.socket.setBuffer(true);
  };

  /**
   * Creates a new JSONP poll that can be used to listen
   * for messages from the Socket.IO server.
   *
   * @api private
   */

  JSONPPolling.prototype.get = function () {
    var self = this
      , script = document.createElement('script')
      , query = io.util.query(
             this.socket.options.query
          , 't='+ (+new Date) + '&i=' + this.index
        );

    if (this.script) {
      this.script.parentNode.removeChild(this.script);
      this.script = null;
    }

    script.async = true;
    script.src = this.prepareUrl() + query;
    script.onerror = function () {
      self.onClose();
    };

    var insertAt = document.getElementsByTagName('script')[0];
    insertAt.parentNode.insertBefore(script, insertAt);
    this.script = script;

    if (indicator) {
      setTimeout(function () {
        var iframe = document.createElement('iframe');
        document.body.appendChild(iframe);
        document.body.removeChild(iframe);
      }, 100);
    }
  };

  /**
   * Callback function for the incoming message stream from the Socket.IO server.
   *
   * @param {String} data The message
   * @api private
   */

  JSONPPolling.prototype._ = function (msg) {
    this.onData(msg);
    if (this.isOpen) {
      this.get();
    }
    return this;
  };

  /**
   * The indicator hack only works after onload
   *
   * @param {Socket} socket The socket instance that needs a transport
   * @param {Function} fn The callback
   * @api private
   */

  JSONPPolling.prototype.ready = function (socket, fn) {
    var self = this;
    if (!indicator) return fn.call(this);

    io.util.load(function () {
      fn.call(self);
    });
  };

  /**
   * Checks if browser supports this transport.
   *
   * @return {Boolean}
   * @api public
   */

  JSONPPolling.check = function () {
    return 'document' in global;
  };

  /**
   * Check if cross domain requests are supported
   *
   * @returns {Boolean}
   * @api public
   */

  JSONPPolling.xdomainCheck = function () {
    return true;
  };

  /**
   * Add the transport to your public io.transports array.
   *
   * @api private
   */

  io.transports.push('jsonp-polling');

})(
    'undefined' != typeof io ? io.Transport : module.exports
  , 'undefined' != typeof io ? io : module.parent.exports
  , this
);

if (typeof define === "function" && define.amd) {
  define([], function () { return io; });
}
})();BigInteger = (function() {
// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return (this.s<0)?-r:r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);

// Copyright (c) 2005-2009  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Extended JavaScript BN functions, required for RSA private ops.

// Version 1.1: new BigInteger("0", 10) returns "proper" zero
// Version 1.2: square() API, isProbablePrime fix

// (public)
function bnClone() { var r = nbi(); this.copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d,y,z);
  while(y.signum() > 0) {
    r = (a+z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d,y,z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string
function bnpFromRadix(s,b) {
  this.fromInt(0);
  if(b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this.dMultiply(Math.pow(b,j));
    this.dAddOffset(w,0);
  }
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
  if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	// force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); // force odd
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB-(i*this.DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
      r[k++] = d|(this.s<<(this.DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this.DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this.DB; --i; }
      }
      if((d&0x80) != 0) d |= -256;
      if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this.DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this.DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r.clamp();
}

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this.changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this.changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this.changeBit(n,op_xor); }

// (protected) r = this + a
function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this.DV+c;
  r.t = i;
  r.clamp();
}

// (public) this + a
function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

// (public) this^2
function bnSquare() { var r = nbi(); this.squareTo(r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n,w) {
  if(n == 0) return;
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this.DV) {
    this[w] -= this.DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this.exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
  else if(x.compareTo(this.m) < 0) return x;
  else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
function bnModPow(e,m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z.convert(this);
  if(k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z.mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this.DB; --j; }
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
      if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z.mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z.sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this.DB-1; --j; }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s<0)?this.negate():this.clone();
  var y = (a.s<0)?a.negate():a.clone();
  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x.rShiftTo(g,x);
    y.rShiftTo(g,y);
  }
  while(x.signum() > 0) {
    if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
    if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
    if(x.compareTo(y) >= 0) {
      x.subTo(y,x);
      x.rShiftTo(1,x);
    }
    else {
      y.subTo(x,y);
      y.rShiftTo(1,y);
    }
  }
  if(g > 0) y.lShiftTo(g,y);
  return y;
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven();
  if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u.signum() != 0) {
    while(u.isEven()) {
      u.rShiftTo(1,u);
      if(ac) {
        if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
        a.rShiftTo(1,a);
      }
      else if(!b.isEven()) b.subTo(m,b);
      b.rShiftTo(1,b);
    }
    while(v.isEven()) {
      v.rShiftTo(1,v);
      if(ac) {
        if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
        c.rShiftTo(1,c);
      }
      else if(!d.isEven()) d.subTo(m,d);
      d.rShiftTo(1,d);
    }
    if(u.compareTo(v) >= 0) {
      u.subTo(v,u);
      if(ac) a.subTo(c,a);
      b.subTo(d,b);
    }
    else {
      v.subTo(u,v);
      if(ac) c.subTo(a,c);
      d.subTo(b,d);
    }
  }
  if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if(d.compareTo(m) >= 0) return d.subtract(m);
  if(d.signum() < 0) d.addTo(m,d); else return d;
  if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x.isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    //Pick bases at random, instead of starting at 2
    a.fromInt(lowprimes[Math.floor(Math.random()*lowprimes.length)]);
    var y = a.modPow(r,this);
    if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2,this);
        if(y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if(y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// JSBN-specific extension
BigInteger.prototype.square = bnSquare;

return BigInteger;
})();

SRPClient = (function() {
/*
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Copyright (C) Paul Johnston 2000.
 * See http://pajhome.org.uk/site/legal.html for details.
 */
/*
 * Modified by Tom Wu (tjw@cs.stanford.edu) for the
 * SRP JavaScript implementation.
 */

/*
 * Convert a 32-bit number to a hex string with ms-byte first
 */
var hex_chr = "0123456789abcdef";
function hex(num)
{
  var str = "";
  for(var j = 7; j >= 0; j--)
    str += hex_chr.charAt((num >> (j * 4)) & 0x0F);
  return str;
}

/*
 * Convert a string to a sequence of 16-word blocks, stored as an array.
 * Append padding bits and the length, as described in the SHA1 standard.
 */
function str2blks_SHA1(str)
{
  var nblk = ((str.length + 8) >> 6) + 1;
  var blks = new Array(nblk * 16);
  for(var i = 0; i < nblk * 16; i++) blks[i] = 0;
  for(i = 0; i < str.length; i++)
    blks[i >> 2] |= str.charCodeAt(i) << (24 - (i % 4) * 8);
  blks[i >> 2] |= 0x80 << (24 - (i % 4) * 8);
  blks[nblk * 16 - 1] = str.length * 8;
  return blks;
}

/*
 * Input is in hex format - trailing odd nibble gets a zero appended.
 */
function hex2blks_SHA1(hex)
{
  var len = (hex.length + 1) >> 1;
  var nblk = ((len + 8) >> 6) + 1;
  var blks = new Array(nblk * 16);
  for(var i = 0; i < nblk * 16; i++) blks[i] = 0;
  for(i = 0; i < len; i++)
    blks[i >> 2] |= parseInt(hex.substr(2*i, 2), 16) << (24 - (i % 4) * 8);
  blks[i >> 2] |= 0x80 << (24 - (i % 4) * 8);
  blks[nblk * 16 - 1] = len * 8;
  return blks;
}

function ba2blks_SHA1(ba, off, len)
{
  var nblk = ((len + 8) >> 6) + 1;
  var blks = new Array(nblk * 16);
  for(var i = 0; i < nblk * 16; i++) blks[i] = 0;
  for(i = 0; i < len; i++)
    blks[i >> 2] |= (ba[off + i] & 0xFF) << (24 - (i % 4) * 8);
  blks[i >> 2] |= 0x80 << (24 - (i % 4) * 8);
  blks[nblk * 16 - 1] = len * 8;
  return blks;
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally 
 * to work around bugs in some JS interpreters.
 */
function add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left
 */
function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * Perform the appropriate triplet combination function for the current
 * iteration
 */
function ft(t, b, c, d)
{
  if(t < 20) return (b & c) | ((~b) & d);
  if(t < 40) return b ^ c ^ d;
  if(t < 60) return (b & c) | (b & d) | (c & d);
  return b ^ c ^ d;
}

/*
 * Determine the appropriate additive constant for the current iteration
 */
function kt(t)
{
  return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
         (t < 60) ? -1894007588 : -899497514;
}

/*
 * Take a string and return the hex representation of its SHA-1.
 */
function calcSHA1(str)
{
  return calcSHA1Blks(str2blks_SHA1(str));
}

function calcSHA1Hex(str)
{
  return calcSHA1Blks(hex2blks_SHA1(str));
}

function calcSHA1BA(ba)
{
  return calcSHA1Blks(ba2blks_SHA1(ba, 0, ba.length));
}

function calcSHA1BAEx(ba, off, len)
{
  return calcSHA1Blks(ba2blks_SHA1(ba, off, len));
}

function calcSHA1Blks(x)
{
  var s = calcSHA1Raw(x);
  return hex(s[0]) + hex(s[1]) + hex(s[2]) + hex(s[3]) + hex(s[4]);
}

function calcSHA1Raw(x)
{
  var w = new Array(80);

  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;
  var e = -1009589776;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;
    var olde = e;

    for(var j = 0; j < 80; j++)
    {
      var t;
      if(j < 16) w[j] = x[i + j];
      else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
      t = add(add(rol(a, 5), ft(j, b, c, d)), add(add(e, w[j]), kt(j)));
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = t;
    }

    a = add(a, olda);
    b = add(b, oldb);
    c = add(c, oldc);
    d = add(d, oldd);
    e = add(e, olde);
  }
  return new Array(a, b, c, d, e);
}

function core_sha1(x, len) {
  x[len >> 5] |= 0x80 << (24 - len % 32)
  x[((len + 64 >> 9) << 4) + 15] = len
  return calcSHA1Raw(x)
}

/*
 * Construct an SRP object with a username,
 * password, and the bits identifying the 
 * group (1024 [default], 1536 or 2048 bits).
 */
SRPClient = function (username, password, group, hashFn) {
  
  // Verify presence of username.
  if (!username)
    throw 'Username cannot be empty.'
    
  // Store username/password.
  this.username = username;
  this.password = password;
  
  // Initialize hash function
  this.hashFn = hashFn || 'sha-1';
  
  // Retrieve initialization values.
  var group = group || 1024;
  var initVal = this.initVals[group];
  
  // Set N and g from initialization values.
  this.N = new BigInteger(initVal.N, 16);
  this.g = new BigInteger(initVal.g, 16);
  this.gBn = new BigInteger(initVal.g, 16);
  
  // Pre-compute k from N and g.
  this.k = this.k();
  
  // Convenience big integer objects for 1 and 2.
  this.one = new BigInteger("1", 16);
  this.two = new BigInteger("2", 16);
  
};

var bcrypt = dcodeIO.bcrypt;

/*
 * Implementation of an SRP client conforming
 * to the SRP protocol 6A (see RFC5054).
 */
SRPClient.prototype = {

  /*
   * Calculate k = H(N || g), which is used
   * throughout various SRP calculations.
   */
  k: function() {
    
    // Convert to hex values.
    var toHash = [
      this.N.toString(16),
      this.g.toString(16)
    ];
    
    // Return hash as a BigInteger.
    return this.paddedHash(toHash);

  },
  
  /*
   * Calculate x = SHA1(s | SHA1(I | ":" | P))
   */
  calculateX: function (saltHex) {
    
    // Verify presence of parameters.
    if (!saltHex) throw 'Missing parameter.'
    
    if (!this.username || !this.password)
      throw 'Username and password cannot be empty.';
    
    // Hash the concatenated username and password.
    var usernamePassword = this.username + ":" + this.password;
    var usernamePasswordHash = bcrypt.hashSync(usernamePassword, saltHex);

    // Calculate the padding for the salt.
    var spad = (saltHex.length % 2 != 0) ? '0' : '';
    
    // Calculate the hash of salt + hash(username:password).
    var X = this.hexHash(spad + saltHex + usernamePasswordHash);
    
    // Return X as a BigInteger.
    return new BigInteger(X, 16);
    
  },
  
  /*
   * Calculate v = g^x % N
   */
  calculateV: function(salt) {
    
    // Verify presence of parameters.
    if (!salt) throw 'Missing parameter.';
    
    // Get X from the salt value.
    var x = this.calculateX(salt);
    
    // Calculate and return the verifier.
    return this.g.modPow(x, this.N);
    
  },
  
  /*
   * Calculate u = SHA1(PAD(A) | PAD(B)), which serves
   * to prevent an attacker who learns a user's verifier
   * from being able to authenticate as that user.
   */
  calculateU: function(A, B) {
    
    // Verify presence of parameters.
    if (!A || !B) throw 'Missing parameter(s).';
    
    // Verify value of A and B.
    if (A.mod(this.N).toString() == '0' ||
        B.mod(this.N).toString() == '0')
      throw 'ABORT: illegal_parameter';
    
    // Convert A and B to hexadecimal.
    var toHash = [A.toString(16), B.toString(16)];
    
    // Return hash as a BigInteger.
    return this.paddedHash(toHash);

  },
  
  /*
   * 2.5.4 Calculate the client's public value A = g^a % N,
   * where a is a random number at least 256 bits in length.
   */
  calculateA: function(a) {
    
    // Verify presence of parameter.
    if (!a) throw 'Missing parameter.';
    
    if (Math.ceil(a.bitLength() / 8) < 256/8)
      throw 'Client key length is less than 256 bits.'
    
    // Return A as a BigInteger.
    var A = this.g.modPow(a, this.N);
    
    if (A.mod(this.N).toString() == '0')
      throw 'ABORT: illegal_parameter';
    
    return A;
    
  },
  
  /*
   * Calculate match M = H(A, B, K) or M = H(A, M, K)
   */
  calculateM: function (A, B_or_M, K) {
    
    // Verify presence of parameters.
    if (!A || !B_or_M || !K)
      throw 'Missing parameter(s).';
    
    // Verify value of A and B.
    if (A.mod(this.N).toString() == '0' ||
        B_or_M.mod(this.N).toString() == '0')
      throw 'ABORT: illegal_parameter';
    
    var aHex = A.toString(16);
    var bHex = B_or_M.toString(16);
    
    var array = [aHex, bHex, K];

    return this.paddedHash(array);
    
  },

  /*
   * Calculate match M1 = H(A | B | S)
   * As seen in Mozilla's node-srp
   */
  calculateMozillaM1: function (A, B, S) {

    // Verify presence of parameters.
    if (!A || !B || !S)
      throw 'Missing parameter(s).';

    // Verify value of A and B.
    if (A.mod(this.N).toString() == '0' ||
        B.mod(this.N).toString() == '0')
      throw 'ABORT: illegal_parameter';

    var aHex = A.toString(16);
    var bHex = B.toString(16);
    var sHex = S.toString(16);

    return this.paddedHash([aHex, bHex, sHex]);

  },

  /*
   * Calculate match M2 = H(A | M | K)
   * As seen in Mozilla's node-srp
   */
  calculateMozillaM2: function (A, M, K) {

    // Verify presence of parameters.
    if (!A || !M || !K)
      throw 'Missing parameter(s).';

    // Verify value of A and B.
    if (A.mod(this.N).toString() == '0')
      throw 'ABORT: illegal_parameter';

    var aHex = A.toString(16);
    var mHex = M.toString(16);
    var kHex = K.toString(16);

    // can't send though paddedHash because it wants to make everything 512
    aHex = this.nZeros(512 - aHex.length) + aHex;
    mHex = this.nZeros(64 - mHex.length) + mHex;
    kHex = this.nZeros(64 - kHex.length) + kHex;

    return this.hexHash(aHex + mHex + kHex);

  },

  /*
   * Calculate the client's premaster secret
   * S = (B - (k * g^x)) ^ (a + (u * x)) % N
   */
  calculateS: function(B, salt, uu, aa) {
    
    // Verify presence of parameters.
    if (!B || !salt || !uu || !aa)
      throw 'Missing parameters.';
    
    // Verify value of B.
    if (B.mod(this.N).toString() == '0')
      throw 'ABORT: illegal_parameter';
      
    // Calculate X from the salt.
    var x = this.calculateX(salt);
    
    // Calculate bx = g^x % N
    var bx = this.g.modPow(x, this.N);
    
    // Calculate ((B + N * k) - k * bx) % N
    var btmp = B.add(this.N.multiply(this.k))
    .subtract(bx.multiply(this.k)).mod(this.N);
    
    // Finish calculation of the premaster secret.
    return btmp.modPow(x.multiply(uu).add(aa), this.N);
  
  },
  
  calculateK: function (S) {
    var sHex = S.toString(16);
    sHex = this.nZeros(512 - sHex.length) + sHex;
    return this.hexHash(sHex);
  },
  
  /*
   * Helper functions for random number
   * generation and format conversion.
   */
  
  /* Generate a random big integer */
  srpRandom: function() {

    var words = sjcl.random.randomWords(8,0);
    var hex = sjcl.codec.hex.fromBits(words);
    
    // Verify random number large enough.
    if (hex.length != 64)
      throw 'Invalid random number size.'

    var r = new BigInteger(hex, 16);
    
    if (r.compareTo(this.N) >= 0)
      r = a.mod(this.N.subtract(this.one));

    if(r.compareTo(this.two) < 0)
      r = two;

    return r;

  },
  
  /* Return a random hexadecimal salt */
  randomHexSalt: function() {

    return bcrypt.genSaltSync();

  },
  
  /*
   * Helper functions for hasing/padding.
   */

  /*
  * SHA1 hashing function with padding: input 
  * is prefixed with 0 to meet N hex width.
  */
  paddedHash: function (array) {

   var nlen = 2 * ((this.N.toString(16).length * 4 + 7) >> 3);

   var toHash = '';
   
   for (var i = 0; i < array.length; i++) {
     toHash += this.nZeros(nlen - array[i].length) + array[i];
   }
   
   var hash = new BigInteger(this.hexHash(toHash), 16);
   
   return hash.mod(this.N);

  },

  /* 
   * Generic hashing function.
   */
  hash: function (str) {

    switch (this.hashFn.toLowerCase()) {
      
      case 'sha-256':
        var s = sjcl.codec.hex.fromBits(
                sjcl.hash.sha256.hash(str));
        return this.nZeros(64 - s.length) + s;
      
      case 'sha-1':
      default:
        return calcSHA1(str);
      
    }
  },
  
  /*
   * Hexadecimal hashing function.
   */
  hexHash: function (str) {
    switch (this.hashFn.toLowerCase()) {
      
      case 'sha-256':
        var s = sjcl.codec.hex.fromBits(
                sjcl.hash.sha256.hash(
                sjcl.codec.hex.toBits(str)));
        return this.nZeros(64 - s.length) + s;

      case 'sha-1':
      default:
        return this.hash(this.pack(str));
      
    }
  },
  
  /*
   * Hex to string conversion.
   */
  pack: function(hex) {
    
    // To prevent null byte termination bug
    if (hex.length % 2 != 0) hex = '0' + hex;
    
    i = 0; ascii = '';

    while (i < hex.length/2) {
      ascii = ascii+String.fromCharCode(
      parseInt(hex.substr(i*2,2),16));
      i++;
    }

    return ascii;

  },
  
  /* Return a string with N zeros. */
  nZeros: function(n) {
    
    if(n < 1) return '';
    var t = this.nZeros(n >> 1);
    
    return ((n & 1) == 0) ?
      t + t : t + t + '0';
  
  },
  
  /*
   * SRP group parameters, composed of N (hexadecimal
   * prime value) and g (decimal group generator).
   * See http://tools.ietf.org/html/rfc5054#appendix-A
   */
  initVals: {
    
    1024: {
      N: 'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C' +
         '9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4' +
         '8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29' +
         '7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A' +
         'FD5138FE8376435B9FC61D2FC0EB06E3',
      g: '2'

    },
    
    1536: {
      N: '9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA961' +
         '4B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F843' +
         '80B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0B' +
         'E3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF5' +
         '6EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734A' +
         'F7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E' +
         '8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB',
      g: '2'
    },
    
    2048: {
      N: 'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294' +              
         '3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D' +
         'CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB' +
         'D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74' +
         '7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A' +
         '436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D' +
         '5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73' +
         '03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6' +
         '94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F' +
         '9E4AFF73',
      g: '2'
    },
    
    3072: {
      N: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08' +
         '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B' +
         '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9' +
         'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6' +
         '49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8' +
         'FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
         '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C' +
         '180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
         '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D' +
         '04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D' +
         'B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226' +
         '1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
         'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC' +
         'E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF',
      g: '5'
    },
    
    4096: {
      N: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08' +
         '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B' +
         '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9' +
         'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6' +
         '49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8' +
         'FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
         '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C' +
         '180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
         '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D' +
         '04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D' +
         'B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226' +
         '1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
         'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC' +
         'E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26' +
         '99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB' +
         '04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' +
         '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127' +
         'D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199' +
         'FFFFFFFFFFFFFFFF',
      g: '5'
    },
    
    6144: {
      N: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08' +
         '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B' +
         '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9' +
         'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6' +
         '49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8' +
         'FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
         '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C' +
         '180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
         '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D' +
         '04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D' +
         'B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226' +
         '1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
         'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC' +
         'E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26' +
         '99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB' +
         '04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' +
         '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127' +
         'D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492' +
         '36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406' +
         'AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918' +
         'DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151' +
         '2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03' +
         'F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F' +
         'BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA' +
         'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B' +
         'B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632' +
         '387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E' +
         '6DCC4024FFFFFFFFFFFFFFFF',
      g: '5'
    },
    
    8192: {
      N:'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08' +
        '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B' +
        '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9' +
        'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6' +
        '49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8' +
        'FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
        '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C' +
        '180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
        '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D' +
        '04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D' +
        'B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226' +
        '1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
        'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC' +
        'E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26' +
        '99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB' +
        '04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' +
        '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127' +
        'D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492' +
        '36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406' +
        'AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918' +
        'DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151' +
        '2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03' +
        'F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F' +
        'BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA' +
        'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B' +
        'B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632' +
        '387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E' +
        '6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA' +
        '3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C' +
        '5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9' +
        '22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC886' +
        '2F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6' +
        '6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC5' +
        '0846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268' +
        '359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6' +
        'FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71' +
        '60C980DD98EDD3DFFFFFFFFFFFFFFFFF',
      g: '19'
    }
    
  },
  
  /*
   * Server-side SRP functions. These should not
   * be used on the client except for debugging.
   */
  
  /* Calculate the server's public value B. */
  calculateB: function(b, v) {
    
    // Verify presence of parameters.
    if (!b || !v) throw 'Missing parameters.';
    
    var bb = this.g.modPow(b, this.N);
    var B = bb.add(v.multiply(this.k)).mod(this.N);
    
    return B;
    
  },

  /* Calculate the server's premaster secret */
  calculateServerS: function(A, v, u, B) {
    
    // Verify presence of parameters.
    if (!A || !v || !u || !B)
      throw 'Missing parameters.';
    
    // Verify value of A and B.
    if (A.mod(this.N).toString() == '0' ||
        B.mod(this.N).toString() == '0')
      throw 'ABORT: illegal_parameter';
    
    return v.modPow(u, this.N).multiply(A)
           .mod(this.N).modPow(B, this.N);
  }
  
};

return SRPClient;
})();
