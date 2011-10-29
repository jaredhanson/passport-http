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
          done(null, 'secret');
        },
        function(username, options, done) {
          done(null, { username: username });
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
  
  'strategy handling a valid request with qop set to "auth"': {
    topic: function() {
      var strategy = new DigestStrategy({ qop: 'auth' },
        function(username, done) {
          done(null, 'secret');
        },
        function(username, options, done) {
          done(null, { username: username });
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
  
  'strategy handling a valid request with qop set to "auth" and algorithm set to "MD5-sess"': {
    topic: function() {
      var strategy = new DigestStrategy({ qop: 'auth', algorithm: 'MD5-sess' },
        function(username, done) {
          done(null, 'secret');
        },
        function(username, options, done) {
          done(null, { username: username });
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
  
  'strategy handling a request without authorization credentials': {
    topic: function() {
      var strategy = new DigestStrategy(
        function(username, done) {
          done(null, 'secret');
        },
        function(username, options, done) {
          done(null, { username: username });
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
  
  'strategy handling a request that is not verified against specific realm': {
    topic: function() {
      var strategy = new DigestStrategy({ realm: 'Administrators' },
        function(username, done) {
          done(null, 'secret');
        },
        function(username, options, done) {
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
          done(null, 'secret');
        },
        function(username, options, done) {
          done(null, { username: username });
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
          done(null, 'secret');
        },
        function(username, options, done) {
          done(null, { username: username });
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
          done(null, 'secret');
        },
        function(username, options, done) {
          done(null, { username: username });
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
          done(null, 'secret');
        },
        function(username, options, done) {
          done(null, { username: username });
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
          done(null, 'secret');
        },
        function(username, options, done) {
          done(null, { username: username });
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
          done(null, 'secret');
        },
        function(username, options, done) {
          done(null, { username: username });
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
      assert.throws(function() { new BasicStrategy() });
    },
  },
  
  'strategy constructed without a validate callback': {
    'should throw an error': function (strategy) {
      assert.throws(function() { new BasicStrategy(function() {}) });
    },
  },
  
}).export(module);
