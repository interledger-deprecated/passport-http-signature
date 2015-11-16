'use strict'
const inherits = require('util').inherits
const passport = require('passport-strategy')
const httpSignature = require('http-signature')

// This is a passport strategy implementing "Signing HTTP Messages":
//   <http://tools.ietf.org/html/draft-cavage-http-signatures-05>
//
// Example request header:
//   Authorization: Signature
//     keyId="rsa-key-1",
//     algorithm="rsa-sha256",
//     headers="(request-target) host date digest content-length",
//     signature="Base64(RSA-SHA256(signing string))"
//
// options -
//   realm   - String (default: "Users")
//   headers - [String]
//     Headers that the server should suggest on 401.
//     "(request-target)" and "date" are automatically included.
// getUserAndKey(keyId, function(err, user, key))
function Strategy (options, getUserAndKey) {
  if (getUserAndKey === undefined) {
    getUserAndKey = options
    options = {}
  }
  passport.Strategy.call(this)
  this.name = 'http-signature'
  this._getUserAndKey = getUserAndKey

  let realm = options.realm || 'Users'
  this._headers = ['(request-target)', 'date']
    .concat(options.headers || [])
    .map(toLowerCase)
  this._headerString = this._headers.join(' ')
  this._challengeString = 'Signature realm="' + realm + '",headers="' + this._headerString + '"'
}

inherits(Strategy, passport.Strategy)

Strategy.prototype.authenticate = function (request) {
  let parsed
  try {
    parsed = httpSignature.parseRequest(request)
  } catch (e) {
    return this._challenge()
  }

  // Verify the signature.
  let _this = this
  this._getUserAndKey(parsed.params.keyId, function (err, user, key) {
    if (err) { return _this.error(err) }
    if (!user || !key) { return _this._challenge() }
    try {
      if (httpSignature.verifySignature(parsed, key)) {
        _this.success(user)
      } else {
        _this._challenge()
      }
    } catch (e) {
      // An unsupported algorithm was used.
      // "Error: Unknown message digest"
      _this._challenge()
    }
  })
}

Strategy.prototype._challenge = function () { this.fail(this._challengeString) }

function toLowerCase (str) { return str.toLowerCase() }

module.exports = Strategy
module.exports.Strategy = Strategy
