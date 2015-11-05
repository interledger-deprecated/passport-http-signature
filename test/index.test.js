'use strict'
/* eslint-env mocha */

const fs = require('fs')
const crypto = require('crypto')
const assert = require('assert')
const Strategy = require('../')
const privateKey = fs.readFileSync(__dirname + '/fixtures/private.pem').toString()
const publicKey = fs.readFileSync(__dirname + '/fixtures/public.pem').toString()

/*
  Fixture setup:
    $ openssl genrsa -des3 -out private.pem 2048
    (password: '123456')
    $ openssl rsa -in private.pem -outform PEM -pubout -out public.pem
*/

describe('Strategy', function () {
  describe('constructor', function () {
    it('sets "name"', function () {
      let s = new Strategy({}, fail)
      assert.equal(s.name, 'http-signature')
    })

    it('sets "_getUserAndKey"', function () {
      let s = new Strategy({}, fail)
      assert.equal(s._getUserAndKey, fail)
    })

    it('sets "_challengeString"', function () {
      let s = new Strategy({}, fail)
      assert.equal(s._challengeString, 'Signature realm="Users",headers="(request-target) date"')
    })

    it('sets "_challengeString" with additional headers', function () {
      let s = new Strategy({headers: ['Content-Length', 'Digest']}, fail)
      assert.deepEqual(s._headers, ['(request-target)', 'date', 'content-length', 'digest'])
      assert.equal(s._challengeString, 'Signature realm="Users",headers="(request-target) date content-length digest"')
    })

    it('accepts a custom realm', function () {
      let s = new Strategy({realm: 'Admin'}, fail)
      assert.equal(s._challengeString, 'Signature realm="Admin",headers="(request-target) date"')
    })

    it('can be called without options', function () {
      let s = new Strategy(fail)
      assert.equal(s.name, 'http-signature')
      assert.equal(s._getUserAndKey, fail)
    })
  })

  describe('.authenticate', function () {
    it('on success: passes the "user" to .success()', function (done) {
      let user = {}
      let s = new Strategy({}, function (keyId, callback) {
        assert.equal(keyId, 'some key')
        callback(null, user, publicKey)
      })
      s.success = function (_user) {
        assert.equal(_user, user)
        done()
      }
      s.authenticate(makeRequest({}))
    })

    it('supports extra headers', function (done) {
      let user = {}
      let s = new Strategy({}, function (keyId, callback) { callback(null, user, publicKey) })
      s.success = function (_user) {
        assert.equal(_user, user)
        done()
      }
      s.authenticate(makeRequest({
        headers: {host: 'example.com'},
        auth: {
          params: {
            headers: '(request-target) date host',
            signature: ['(request-target)', 'date', 'host']
          }
        }
      }))
    })

    it('on getUserAndKey error: error', function (done) {
      let err = new Error()
      let s = new Strategy({}, function (keyId, callback) { callback(err) })
      s.error = function (_err) {
        assert.equal(_err, err)
        done()
      }
      s.authenticate(makeRequest({}))
    })

    ;[
      {
        desc: 'on missing Authorization header: return challenge',
        headers: { authorization: '' }
      },
      {
        desc: 'on incorrect scheme: return challenge',
        auth: { scheme: 'Wrong' }
      },
      {
        desc: 'on missing keyId: return challenge',
        auth: { params: {keyId: null} }
      },
      {
        desc: 'on empty keyId: return challenge',
        auth: { params: {keyId: ''} }
      },
      {
        desc: 'on missing algorithm: return challenge',
        auth: { params: {algorithm: null} }
      },
      {
        desc: 'on empty algorithm: return challenge',
        auth: { params: {algorithm: ''} }
      },
      {
        desc: 'on missing headers: return challenge',
        auth: { params: {headers: null} }
      },
      {
        desc: 'on empty headers: return challenge',
        auth: { params: {headers: ''} }
      },
      {
        desc: 'on bogus headers: return challenge',
        auth: { params: {headers: 'foo bar'} }
      },
      {
        desc: 'on missing signature: return challenge',
        auth: { params: {signature: null} }
      },
      {
        desc: 'on empty signature: return challenge',
        auth: { params: {signature: ''} }
      }
    ].forEach(function (params) {
      it(params.desc, function (done) {
        let s = new Strategy({}, fail)
        s.fail = makeFail(done)
        s.authenticate(makeRequest(params))
      })
    })

    it('on invalid signature: challenge', function (done) {
      let user = {}
      let s = new Strategy({}, function (keyId, callback) {
        assert.equal(keyId, 'some key')
        callback(null, user, publicKey)
      })
      s.fail = makeFail(done)
      s.authenticate(makeRequest({
        auth: {params: {signature: sign('wrong wrong wrong')}}
      }))
    })

    it('on bogus algorithm: challenge', function (done) {
      let user = {}
      let s = new Strategy({}, function (keyId, callback) {
        assert.equal(keyId, 'some key')
        callback(null, user, publicKey)
      })
      s.fail = makeFail(done)
      s.authenticate(makeRequest({
        auth: {params: {algorithm: 'rsa-sha255'}}
      }))
    })
  })
})

// opts -
//   method  - String
//   path    - String
//   headers - Object
//   auth    - {scheme, params}
//     scheme - String "Signature"
//     params -
//       keyId     - String
//       algorithm - String
//       headers   - String
//       signature - String | {header: value} | [String header]
function makeRequest (opts) { return new Request(opts) }

function Request (opts) {
  this.method = opts.method || 'GET'
  this.path = opts.path || '/foo'
  this.headers = extend({
    'date': (new Date()).toUTCString(),
    'content-length': '1234'
  }, opts.headers || {})
  if (this.headers.authorization == null) {
    this.headers.authorization = this._makeAuthorization(opts.auth || {})
  }
}

Request.prototype._makeAuthorization = function (auth) {
  const params = extend({
    keyId: 'some key',
    algorithm: 'rsa-sha256',
    headers: '(request-target) date'
  }, auth.params || {})
  if (!(auth.params && auth.params.signature === null)) {
    params.signature = this._makeSignature(params.signature)
  }
  return (auth.scheme || 'Signature') + ' ' +
    Object.keys(params).map(function (attr) {
      return attr + '="' + params[attr] + '"'
    }).join(',')
}

Request.prototype._makeSignature = function (opts) {
  if (typeof opts === 'string') return opts
  return sign(this._makeSignatureString(opts))
}

// opts - String | {header : value} | [String header]
Request.prototype._makeSignatureString = function (opts) {
  if (!opts) opts = ['(request-target)', 'date']
  if (opts instanceof Array) {
    return opts.map(function (header) {
      return header + ': ' + this._getHeader(header)
    }, this).join('\n')
  } else {
    return Object.keys(opts).map(function (header) {
      return header + ': ' + opts[header]
    }).join('\n')
  }
}

Request.prototype._getHeader = function (header) {
  return header === '(request-target)'
       ? (this.method.toLowerCase() + ' ' + this.path)
       : (this.headers[header] || '')
}

function extend (obj, extras) {
  for (let key in extras) {
    let value = extras[key]
    if (value === null) delete obj[key]
    else obj[key] = value
  }
  return obj
}

function sign (message) {
  return crypto.createSign('RSA-SHA256')
    .update(message)
    .sign({key: privateKey, passphrase: '123456'}, 'base64')
}

function makeFail (done) {
  return function (_challenge) {
    assert.equal(_challenge, this._challengeString)
    done()
  }
}

function fail () { throw new Error('This shouldnt have been called') }
