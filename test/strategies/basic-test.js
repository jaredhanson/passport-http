var vows = require('vows');
var assert = require('assert');
var util = require('util');
var BasicStrategy = require('passport-http/strategies/basic');


vows.describe('BasicStrategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new BasicStrategy(function() {});
    },
    
    'should be named basic': function (strategy) {
      assert.equal(strategy.name, 'basic');
    },
  },
  
  'strategy handling a request': {
    topic: function() {
      var strategy = new BasicStrategy(function(userid, password, done) {
        done(null, { username: userid, password: password });
      });
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
        
        req.headers = {};
        req.headers.authorization = 'Basic Ym9iOnNlY3JldA==';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'bob');
        assert.equal(user.password, 'secret');
      },
    },
  },

  'strategy handling a request that is not verified': {
    topic: function() {
      var strategy = new BasicStrategy(function(userid, password, done) {
        done(null, false);
      });
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
        req.headers.authorization = 'Basic Ym9iOnNlY3JldA==';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 'Basic realm="Users"');
      },
    },
  },
  
  'strategy handling a request that encounters an error during verification': {
    topic: function() {
      var strategy = new BasicStrategy(function(userid, password, done) {
        done(new Error('something went wrong'));
      });
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
        
        req.headers = {};
        req.headers.authorization = 'Basic Ym9iOnNlY3JldA==';
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
      var strategy = new BasicStrategy(function(userid, password, done) {
        done(null, { username: userid, password: password });
      });
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
        assert.equal(challenge, 'Basic realm="Users"');
      },
    },
  },
  
  'strategy handling a request with non-Basic authorization credentials': {
    topic: function() {
      var strategy = new BasicStrategy(function(userid, password, done) {
        done(null, { username: userid, password: password });
      });
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
        req.headers.authorization = 'XXXXX Ym9iOnNlY3JldA==';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 'Basic realm="Users"');
      },
    },
  },
  
  'strategy handling a request with credentials lacking a password': {
    topic: function() {
      var strategy = new BasicStrategy(function(userid, password, done) {
        done(null, { username: userid, password: password });
      });
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
        req.headers.authorization = 'Basic Ym9iOg==';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 'Basic realm="Users"');
      },
    },
  },
  
  'strategy handling a request with credentials lacking a username': {
    topic: function() {
      var strategy = new BasicStrategy(function(userid, password, done) {
        done(null, { username: userid, password: password });
      });
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
        req.headers.authorization = 'Basic OnNlY3JldA==';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 'Basic realm="Users"');
      },
    },
  },
  
  'strategy handling a request with malformed authorization header': {
    topic: function() {
      var strategy = new BasicStrategy(function(userid, password, done) {
        done(null, { username: userid, password: password });
      });
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
        
        req.headers = {};
        req.headers.authorization = 'Basic';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 400);
      },
    },
  },
  
  'strategy handling a request with malformed authorization credentials': {
    topic: function() {
      var strategy = new BasicStrategy(function(userid, password, done) {
        done(null, { username: userid, password: password });
      });
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
        
        req.headers = {};
        req.headers.authorization = 'Basic *****';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 400);
      },
    },
  },
  
  'strategy handling a request with BASIC scheme in capitalized letters': {
    topic: function() {
      var strategy = new BasicStrategy(function(userid, password, done) {
        done(null, { username: userid, password: password });
      });
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
        
        req.headers = {};
        req.headers.authorization = 'BASIC Ym9iOnNlY3JldA==';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'bob');
        assert.equal(user.password, 'secret');
      },
    },
  },
  
  'strategy handling a request that is not verified against specific realm': {
    topic: function() {
      var strategy = new BasicStrategy({ realm: 'Administrators' }, function(userid, password, done) {
        done(null, false);
      });
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
        req.headers.authorization = 'Basic Ym9iOnNlY3JldA==';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 'Basic realm="Administrators"');
      },
    },
  },
  
  'strategy constructed without a verify callback': {
    'should throw an error': function (strategy) {
      assert.throws(function() { new BasicStrategy() });
    },
  },

  'strategy with passReqToCallback=true option': {
    topic: function() {
      var strategy = new BasicStrategy({passReqToCallback:true}, function(req, userid, password, done) {
        assert.isNotNull(req);
        done(null, { username: userid, password: password });
      });
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
        
        req.headers = {};
        req.headers.authorization = 'Basic Ym9iOnNlY3JldA==';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'bob');
        assert.equal(user.password, 'secret');
      },
    },
  },

}).export(module);
