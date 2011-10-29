var express = require('express')
  , passport = require('passport')
  , util = require('util')
  , DigestStrategy = require('passport-http').DigestStrategy;


var users = [
    { id: 1, username: 'bob', password: 'secret', email: 'bob@example.com' }
  , { id: 2, username: 'joe', password: 'birthday', email: 'joe@example.com' }
];

function findByUsername(username, fn) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
    if (user.username === username) {
      return fn(null, user);
    }
  }
  return fn(null, null);
}


// Use the DigestStrategy within Passport.
//   This strategy requires a `secret`function, which is used to look up the
//   password known to both the client and server.  Also required is a
//   `validate` function, which accepts credentials (in this case, a username
//   and nonce-related options), and invokes a callback with a user object.
passport.use(new DigestStrategy({ qop: 'auth' },
  function(username, done) {
    // Find the user by username.  If there is no user with the given username
    // set the user to `false` to indicate failure.  Otherwise, return the
    // user's password.
    findByUsername(username, function(err, user) {
      if (err) { return done(err); }
      if (!user) { return done(null, false); }
      return done(null, user.password);
    })
  },
  function(username, password, done) {
    // asynchronous validation, for effect...
    process.nextTick(function () {
      
      // Find the user by username.  If there is no user with the given
      // username, set the user to `false` to indicate failure.  Otherwise,
      // return the authenticated `user`.
      findByUsername(username, function(err, user) {
        if (err) { return done(err); }
        if (!user) { return done(null, false); }
        return done(null, user);
      })
    });
  }
));




var app = express.createServer();

// configure Express
app.configure(function() {
  app.use(express.logger());
  // Initialize Passport!  Note: no need to use session middleware when each
  // request carries authentication credentials, as is the case with HTTP
  // Digest.
  app.use(passport.initialize());
  app.use(app.router);
  app.use(express.static(__dirname + '/public'));
});


// curl -v -I http://127.0.0.1:3000/
// curl -v -I --user bob:secret --digest http://127.0.0.1:3000/
// curl -v -d "hello=world" --user bob:secret --digest http://127.0.0.1:3000/
app.all('/',
  // Authenticate using HTTP Digest credentials, with session support disabled.
  passport.authenticate('digest', { session: false }),
  function(req, res){
    res.json({ username: req.user.username, email: req.user.email });
  });

app.listen(3000);
