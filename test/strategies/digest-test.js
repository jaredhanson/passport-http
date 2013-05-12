var vows = require('vows');
var assert = require('assert');
var util = require('util');
var DigestStrategy = require('passport-http/strategies/digest');


vows.describe('DigestStrategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new DigestStrategy(
        function() {},
        function() {}
      );
    },
    
    'should be named digest': function (strategy) {
      assert.equal(strategy.name, 'digest');
    },
  },
  
  'strategy handling a valid request': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS", uri="/", response="22e3e0a9bbefeb9d229905230cb9ddc8"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'bob');
      },
    },
  },


  'strategy handling a valid request with an empty username': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="", realm="Users", nonce="NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS", uri="/", response="459ea26315b4ac2ad14537695acd5a9b"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should fail authentication with challenge' : function(err, challenge) {
        assert.match(challenge, /^Digest realm="Users", nonce="\w{32}"$/);
      },
    },
  },
  
  'strategy handling a valid request with credentials not separated by spaces': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob",realm="Users",nonce="NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS",uri="/",response="22e3e0a9bbefeb9d229905230cb9ddc8"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'bob');
      },
    },
  },
  
  'strategy handling a valid request and supplying hashed HA1 to secret callback': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, { username: username }, { ha1: '9e3bcfb22c441e9648cae34400c648d0' });
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS", uri="/", response="22e3e0a9bbefeb9d229905230cb9ddc8"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'bob');
      },
    },
  },
  
  'strategy handling a valid request without optional validate callback': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, { username: username }, 'secret');
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS", uri="/", response="22e3e0a9bbefeb9d229905230cb9ddc8"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'bob');
      },
    },
  },
  
  'strategy handling a valid request with algorithm set to "MD5"': {
    topic: function() {
      var strategy = new DigestStrategy({ algorithm: 'MD5' },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="720rZDMBH44rIsKKSz75zd0fMvcQaL8Y", uri="/", response="1db489e2049a77d27b6f05c917f9aa58", algorithm="MD5"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'bob');
      },
    },
  },
  
  'strategy handling a valid request with qop set to "auth"': {
    topic: function() {
      var strategy = new DigestStrategy({ qop: 'auth' },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          if (options.nonce === 'T1vogipt8GzzWyCZt7U3TNV5XsarMW8y' && options.cnonce === 'MTMxOTkx' && options.nc === '00000001') {
            done(null, true);
          } else {
            done(new Error('something is wrong'))
          }
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="T1vogipt8GzzWyCZt7U3TNV5XsarMW8y", uri="/", cnonce="MTMxOTkx", nc=00000001, qop="auth", response="7495a912e5c52e1e9ac92793c6f5c229"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'bob');
      },
    },
  },
  
  'strategy handling a valid request with qop set to "auth" and equal sign in URL': {
    topic: function() {
      var strategy = new DigestStrategy({ qop: 'auth' },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          if (options.nonce === '3sauEztFK9HB2vjADmXE4sQbtwpGCFZ2' && options.cnonce === 'MTM0MTkw' && options.nc === '00000001') {
            done(null, { nonce: options.nonce, cnonce: options.cnonce, nc: options.nc });
          } else {
            done(new Error('something is wrong'))
          }
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/sessions.json?sEcho=2&iColumns=12';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="3sauEztFK9HB2vjADmXE4sQbtwpGCFZ2", uri="/sessions.json?sEcho=2&iColumns=12", cnonce="MTM0MTkw", nc=00000001, qop="auth", response="83e2cb1afbb943a0cde78290c5002607"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'bob');
      },
    },
  },
  
  'strategy handling a valid request with credentials not separated by spaces with qop set to "auth" and equal sign in URL': {
    topic: function() {
      var strategy = new DigestStrategy({ qop: 'auth' },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          if (options.nonce === '3sauEztFK9HB2vjADmXE4sQbtwpGCFZ2' && options.cnonce === 'MTM0MTkw' && options.nc === '00000001') {
            done(null, { nonce: options.nonce, cnonce: options.cnonce, nc: options.nc });
          } else {
            done(new Error('something is wrong'))
          }
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/sessions.json?sEcho=2&iColumns=12';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob",realm="Users",nonce="3sauEztFK9HB2vjADmXE4sQbtwpGCFZ2",uri="/sessions.json?sEcho=2&iColumns=12",cnonce="MTM0MTkw",nc=00000001,qop="auth",response="83e2cb1afbb943a0cde78290c5002607"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'bob');
      },
    },
  },
  
  'strategy handling a valid request with qop set to "auth" and algorithm set to "MD5-sess"': {
    topic: function() {
      var strategy = new DigestStrategy({ qop: 'auth', algorithm: 'MD5-sess' },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="Ag1nqGybX7GXpXGWjTJs0pCCRboeLnbI", uri="/", cnonce="MTMxOTkx", nc=00000001, qop="auth", response="db5b2989137bf89622d8cb1ea583eec9", algorithm="MD5-sess"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'bob');
      },
    },
  },
  
  'strategy handling an invalid request with qop set to "auth-int" and auth-int support not implemented': {
    topic: function() {
      var strategy = new DigestStrategy({ qop: 'auth-int' },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, err);
        }
        
        req.url = '/';
        req.method = 'POST';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="2HQNNVPOZXBz47jSs3POzWDJn15xSsJp", uri="/", cnonce="MTMxOTky", nc=00000001, qop="auth-int", response="9c63f9e51406979ba661dd820cc21122"';
        // TODO: When support for auth-int is implemented, a raw entity body
        //       will need to be provided.
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, e) {
        assert.isNull(err);
      },
      'should call error' : function(err, e) {
        assert.instanceOf(e, Error);
      },
    },
  },
  
  'strategy handling a request with invalid password': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, { username: username }, 'idontknow');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS", uri="/", response="22e3e0a9bbefeb9d229905230cb9ddc8"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.match(challenge, /^Digest realm="Users", nonce="\w{32}"$/);
      },
    },
  },
  
  'strategy handling a request that does not have a shared secret': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, false);
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS", uri="/", response="22e3e0a9bbefeb9d229905230cb9ddc8"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.match(challenge, /^Digest realm="Users", nonce="\w{32}"$/);
      },
    },
  },
  
  'strategy handling a request that is not validated': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, false);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS", uri="/", response="22e3e0a9bbefeb9d229905230cb9ddc8"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.match(challenge, /^Digest realm="Users", nonce="\w{32}"$/);
      },
    },
  },
  
  'strategy handling a request that encounters an error while finding shared secret': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(new Error('something went wrong'));
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, err);
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS", uri="/", response="22e3e0a9bbefeb9d229905230cb9ddc8"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, e) {
        assert.isNull(err);
      },
      'should call error' : function(err, e) {
        assert.instanceOf(e, Error);
      },
    },
  },
  
  'strategy handling a request that encounters an error during validation': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(new Error('something went wrong'));
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, err);
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS", uri="/", response="22e3e0a9bbefeb9d229905230cb9ddc8"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, e) {
        assert.isNull(err);
      },
      'should call error' : function(err, e) {
        assert.instanceOf(e, Error);
      },
    },
  },
  
  'strategy handling a request without authorization credentials': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.url = '/';
        req.headers = {};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.match(challenge, /^Digest realm="Users", nonce="\w{32}"$/);
      },
    },
  },
  
  'strategy handling a request with non-Digest authorization credentials': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'XXXXX username="bob", realm="Users", nonce="NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS", uri="/", response="22e3e0a9bbefeb9d229905230cb9ddc8"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.match(challenge, /^Digest realm="Users", nonce="\w{32}"$/);
      },
    },
  },
  
  'strategy handling a request with malformed authorization header': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(status) {
          self.callback(null, status);
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with 400 Bad Request' : function(err, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(status, 400);
      },
    },
  },
  
  'strategy handling a request with malformed authorization credentials': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(status) {
          self.callback(null, status);
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest *****';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with 400 Bad Request' : function(err, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(status, 400);
      },
    },
  },
  
  'strategy handling a request with non-matching uri': {
    topic: function() {
      var strategy = new DigestStrategy({ algorithm: 'MD5' },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(status) {
          self.callback(null, status);
        }
        
        req.url = '/admin';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="720rZDMBH44rIsKKSz75zd0fMvcQaL8Y", uri="/", response="1db489e2049a77d27b6f05c917f9aa58", algorithm="MD5"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with 400 Bad Request' : function(err, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(status, 400);
      },
    },
  },
  
  'strategy handling a request with unknown algorithm': {
    topic: function() {
      var strategy = new DigestStrategy({ algorithm: 'MD5' },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(status) {
          self.callback(null, status);
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="720rZDMBH44rIsKKSz75zd0fMvcQaL8Y", uri="/", response="1db489e2049a77d27b6f05c917f9aa58", algorithm="XXX"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with 400 Bad Request' : function(err, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(status, 400);
      },
    },
  },
  
  'strategy handling a request with unknown quality of protection': {
    topic: function() {
      var strategy = new DigestStrategy({ qop: 'auth' },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(status) {
          self.callback(null, status);
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="T1vogipt8GzzWyCZt7U3TNV5XsarMW8y", uri="/", cnonce="MTMxOTkx", nc=00000001, qop="xxxx", response="7495a912e5c52e1e9ac92793c6f5c229"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with 400 Bad Request' : function(err, status) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(status, 400);
      },
    },
  },
  
  'strategy handling a request with DIGEST scheme in capitalized letters': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.url = '/';
        req.method = 'HEAD';
        req.headers = {};
        req.headers.authorization = 'DIGEST username="bob", realm="Users", nonce="NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS", uri="/", response="22e3e0a9bbefeb9d229905230cb9ddc8"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'bob');
      },
    },
  },
  
  'strategy handling a request that is not verified against specific realm': {
    topic: function() {
      var strategy = new DigestStrategy({ realm: 'Administrators' },
        function(username, done) {
          done(null, false);
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.url = '/';
        req.headers = {};
        req.headers.authorization = 'Digest username="bob", realm="Users", nonce="NOIEDJ3hJtqSKaty8KF8xlkaYbItAkiS", uri="/", response="22e3e0a9bbefeb9d229905230cb9ddc8"';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.match(challenge, /^Digest realm="Administrators", nonce="\w{32}"$/);
      },
    },
  },
  
  'strategy handling a request without authorization credentials with domain option set': {
    topic: function() {
      var strategy = new DigestStrategy({ domain: '/admin' },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.url = '/';
        req.headers = {};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.match(challenge, /^Digest realm="Users", domain="\/admin", nonce="\w{32}"$/);
      },
    },
  },
  
  'strategy handling a request without authorization credentials with multiple domain options set': {
    topic: function() {
      var strategy = new DigestStrategy({ domain: ['/admin', '/private'] },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.url = '/';
        req.headers = {};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.match(challenge, /^Digest realm="Users", domain="\/admin \/private", nonce="\w{32}"$/);
      },
    },
  },
  
  'strategy handling a request without authorization credentials with opaque option set': {
    topic: function() {
      var strategy = new DigestStrategy({ opaque: 'abcdefg1234' },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.url = '/';
        req.headers = {};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.match(challenge, /^Digest realm="Users", nonce="\w{32}", opaque="abcdefg1234"$/);
      },
    },
  },
  
  'strategy handling a request without authorization credentials with algorithm option set': {
    topic: function() {
      var strategy = new DigestStrategy({ algorithm: 'MD5-sess' },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.url = '/';
        req.headers = {};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.match(challenge, /^Digest realm="Users", nonce="\w{32}", algorithm=MD5-sess$/);
      },
    },
  },
  
  'strategy handling a request without authorization credentials with qop option set': {
    topic: function() {
      var strategy = new DigestStrategy({ qop: 'auth' },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.url = '/';
        req.headers = {};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.match(challenge, /^Digest realm="Users", nonce="\w{32}", qop="auth"$/);
      },
    },
  },
  
  'strategy handling a request without authorization credentials with multiple qop options set': {
    topic: function() {
      var strategy = new DigestStrategy({ qop: ['auth', 'auth-int'] },
        function(username, done) {
          done(null, { username: username }, 'secret');
        },
        function(options, done) {
          done(null, true);
        }
      );
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.url = '/';
        req.headers = {};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.match(challenge, /^Digest realm="Users", nonce="\w{32}", qop="auth,auth-int"$/);
      },
    },
  },
  
  'strategy constructed without a secret callback or validate callback': {
    'should throw an error': function (strategy) {
      assert.throws(function() { new DigestStrategy() });
    },
  },
  
}).export(module);
