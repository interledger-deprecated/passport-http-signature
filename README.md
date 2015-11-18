# passport-http-signature

> Passport strategy using HTTP Signatures

[![NPM Version][npm-image]][npm-url]
[![Linux Build][circle-image]][circle-url]
[![Test Coverage][coveralls-image]][coveralls-url]

## Install

```bash
npm install --save passport-http-signature
```

## Usage

### Configure Strategy

    passport.use(new HTTPSignatureStrategy(
      function (username, done) {
        User.findById(username, function(err, user) {
          if (err) return done(err)
          if (!user) return done()
          done(null, user, user.public_key)
        })
      }))

### Authenticate Requests

    app.get('/private',
      passport.authenticate('http-signature'),
      function(req, res) {
        res.json(req.user)
      })

## License

[MIT](https://opensource.org/licenses/ISC)

[npm-image]: https://img.shields.io/npm/v/passport-http-signature.svg
[npm-url]: https://npmjs.org/package/passport-http-signature
[circle-image]: https://img.shields.io/circleci/project/interledger/passport-http-signature.svg
[circle-url]: https://circleci.com/gh/interledger/passport-http-signature
[coveralls-image]: https://img.shields.io/coveralls/interledger/passport-http-signature/master.svg
[coveralls-url]: https://coveralls.io/r/interledger/passport-http-signature?branch=master
