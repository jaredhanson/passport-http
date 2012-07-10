var express = require('express')
  , passport = require('passport')
  , util = require('util')
  , BasicStrategy = require('passport-http').BasicStrategy
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


// Use the BasicStrategy within Passport.
//   Strategies in Passport require a `verify` function, which accept
//   credentials (in this case, a username and password), and invoke a callback
//   with a user object.
passport.use(new BasicStrategy(function(username, password, done) {
  // Find the user by username.  If there is no user with the given
  // username, or the password is not correct, set the user to `false` to
  // indicate failure.  Otherwise, return the authenticated `user`.
  findByUsername(username, function(err, user) {
    if (err) { return done(err); }
    if (!user) { return done(null, false); }
    if (user.password != password) { return done(null, false); }
    return done(null, user);
  })
}));

passport.use(new DigestStrategy({ qop: 'auth' }, function(username, done) {
  // Find the user by username.  If there is no user with the given username
  // set the user to `false` to indicate failure.  Otherwise, return the
  // user and user's password.
  findByUsername(username, function(err, user) {
    if (err) { return done(err); }
    if (!user) { return done(null, false); }
    return done(null, user, user.password);
  })
}));


var app = express.createServer();

// configure Express
app.configure(function() {
  app.use(express.logger());
  // Initialize Passport!  Note: no need to use session middleware when each
  // request carries authentication credentials, as is the case with HTTP Basic.
  app.use(passport.initialize());
  app.use(app.router);
  app.use(express.static(__dirname + '/public'));
});


// curl -v -I http://127.0.0.1:3000/
// curl -v -I --user bob:secret --basic http://127.0.0.1:3000/
// curl -v -I --user bob:secret --digest http://127.0.0.1:3000/
// curl -v -I --user bob:secret --anyauth http://127.0.0.1:3000/
app.get('/',
  // Authenticate using HTTP Basic credentials, with session support disabled.
  passport.authenticate('digest', { session: false }),
  function(req, res){
   res.json({ username: req.user.username, email: req.user.email });
  });

app.listen(3000);
