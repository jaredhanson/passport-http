/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util');


/**
 * `BasicStrategy` constructor.
 *
 * @api public
 */
function BasicStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) throw new Error('HTTP Basic authentication strategy requires a verify function');
  
  passport.Strategy.call(this);
  this.name = 'basic';
  this.verify = verify;
  this._realm = options.realm || 'Users';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(BasicStrategy, passport.Strategy);

BasicStrategy.prototype.authenticate = function(req) {
  var authorization = req.headers['authorization'];
  if (!authorization) { return this.fail(this._challenge()); }
  
  var parts = authorization.split(' ')
  if (parts.length != 2) { return this.fail(this._challenge()); }
  
  var scheme = parts[0]
    , credentials = new Buffer(parts[1], 'base64').toString().split(':');

  if (!/Basic/i.test(scheme)) { return this.fail(this._challenge()); }
  
  var userid = credentials[0];
  var password = credentials[1];
  if (!userid || !password) {
    return this.fail(this._challenge());
  }
  
  var self = this;
  this.verify(userid, password, function(err, user) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(self._challenge()); }
    self.success(user);
  });
}

BasicStrategy.prototype._challenge = function() {
  return 'Basic realm="' + this._realm + '"';
}


/**
 * Expose `BasicStrategy`.
 */ 
module.exports = BasicStrategy;
