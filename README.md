# Passport-HTTP

HTTP Basic and Digest authentication strategies for [Passport](https://github.com/jaredhanson/passport).

This module lets you authenticate HTTP requests using the standard basic and
digest schemes in your Node.js applications.  By plugging into Passport, support
for these schemes can be easily and unobtrusively integrated into any
application or framework that supports [Connect](http://www.senchalabs.org/connect/)-style
middleware, including [Express](http://expressjs.com/).

<div align="center">

:heart: [Sponsors](https://www.passportjs.org/sponsors/?utm_source=github&utm_medium=referral&utm_campaign=passport-http&utm_content=nav-sponsors)

</div>

---

<p align="center">
  <sup>Advertisement</sup>
  <br>
  <a href="https://click.linksynergy.com/link?id=D*o7yui4/NM&offerid=507388.1672410&type=2&murl=https%3A%2F%2Fwww.udemy.com%2Fcourse%2Fnodejs-express-mongodb-bootcamp%2F&u1=kLuTIzmrCT1t6LdTW2psh0IyTCmrtTgnUbaS9Ot">Node.js, Express, MongoDB & More: The Complete Bootcamp 2020</a><br>Master Node by building a real-world RESTful API and web app (with authentication, Node.js security, payments & more)
</p>

---

[![npm](https://img.shields.io/npm/v/passport-http.svg)](https://www.npmjs.com/package/passport-http)
[![build](https://img.shields.io/travis/jaredhanson/passport-http.svg)](https://travis-ci.org/jaredhanson/passport-http)
[![coverage](https://img.shields.io/coveralls/jaredhanson/passport-http.svg)](https://coveralls.io/github/jaredhanson/passport-http)
[...](https://github.com/jaredhanson/passport-http/wiki/Status)

## Install

    $ npm install passport-http

## Usage of HTTP Basic

#### Configure Strategy

The HTTP Basic authentication strategy authenticates users using a userid and
password.  The strategy requires a `verify` callback, which accepts these
credentials and calls `done` providing a user.

    passport.use(new BasicStrategy(
      function(userid, password, done) {
        User.findOne({ username: userid }, function (err, user) {
          if (err) { return done(err); }
          if (!user) { return done(null, false); }
          if (!user.verifyPassword(password)) { return done(null, false); }
          return done(null, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'basic'` strategy, to
authenticate requests.  Requests containing an 'Authorization' header do not
require session support, so the `session` option can be set to `false`.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/private', 
      passport.authenticate('basic', { session: false }),
      function(req, res) {
        res.json(req.user);
      });

#### Examples

For a complete, working example, refer to the [Basic example](https://github.com/passport/express-3.x-http-basic-example).

## Usage of HTTP Digest

#### Configure Strategy

The HTTP Digest authentication strategy authenticates users using a username and
password (aka shared secret).  The strategy requires a `secret` callback, which
accepts a `username` and calls `done` providing a user and password known to the
server.  The password is used to compute a hash, and authentication fails if it
does not match that contained in the request.

The strategy also accepts an optional `validate` callback, which receives
nonce-related `params` that can be further inspected to determine if the request
is valid.

    passport.use(new DigestStrategy({ qop: 'auth' },
      function(username, done) {
        User.findOne({ username: username }, function (err, user) {
          if (err) { return done(err); }
          if (!user) { return done(null, false); }
          return done(null, user, user.password);
        });
      },
      function(params, done) {
        // validate nonces as necessary
        done(null, true)
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'digest'` strategy, to
authenticate requests.  Requests containing an 'Authorization' header do not
require session support, so the `session` option can be set to `false`.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/private', 
      passport.authenticate('digest', { session: false }),
      function(req, res) {
        res.json(req.user);
      });

#### Examples

For a complete, working example, refer to the [Digest example](https://github.com/passport/express-3.x-http-digest-example).

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2011-2013 Jared Hanson <[http://jaredhanson.net/](http://jaredhanson.net/)>
