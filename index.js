'use strict'
const crypto = require('crypto')
const inherits = require('util').inherits
const passport = require('passport-strategy')

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
//     Clients can sign additional headers as well, but these are required,
//     or the request will be rejected.
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
  let authorization = request.headers.authorization
  if (!authorization) {
    return this._challenge()
  }

  let split = authorization.indexOf(' ')
  if (split === -1) { return this.fail(400) }
  let scheme = authorization.slice(0, split)
  let paramsString = authorization.slice(split + 1)
  // Test the scheme
  if (scheme.toLowerCase() !== 'signature') {
    return this._challenge()
  }

  // Test the params
  let params = parseAuthorizationParams(paramsString)
  let algorithm = params.algorithm
  let headers = params.headers && params.headers.split(' ')
  if (!algorithm || !headers ||
   !params.keyId || !params.signature ||
   !this._testHeaders(headers)) {
    return this._challenge()
  }

  // Verify the signature.
  let signatureString = makeSignatureString(headers, request)
  let _this = this
  this._getUserAndKey(params.keyId, function (err, user, key) {
    if (err) { return _this.error(err) }
    if (!user || !key) { return _this._challenge() }
    try {
      let isValid = crypto
        .createVerify(algorithm.toUpperCase())
        .update(signatureString)
        .verify(key, params.signature, 'base64')
      if (isValid) {
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

// Check that this._headers is a subset of headerParams.
Strategy.prototype._testHeaders = function (headerParams) {
  for (let header of this._headers) {
    if (headerParams.indexOf(header) === -1) return false
  }
  return true
}

// auth - 'a="b",c="d"'
function parseAuthorizationParams (auth) {
  let params = {}
  let pattern = /(\w+)="([^"]*)"(?:,|$)/g
  let match
  while ((match = pattern.exec(auth))) {
    params[match[1]] = match[2]
  }
  return params
}

function makeSignatureString (headers, request) {
  let lines = []
  for (let header of headers) {
    if (header === '(request-target)') {
      lines.push('(request-target): ' +
        request.method.toLowerCase() + ' ' + request.path)
    } else {
      lines.push(header + ': ' + (request.headers[header] || ''))
    }
  }
  return lines.join('\n')
}

function toLowerCase (str) { return str.toLowerCase() }

module.exports = Strategy
module.exports.Strategy = Strategy
