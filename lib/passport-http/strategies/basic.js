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
function BasicStrategy(options, validate) {
  options = options || {}
  passport.Strategy.call(this);
  this.name = 'basic';
  this._validate = validate;
  
  this.middleware.push(require('../middleware/basic')());
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(BasicStrategy, passport.Strategy);

BasicStrategy.prototype.authenticate = function(req) {
  if (!req.auth || (!req.auth.userid && !req.auth.password)) {
    return this.unauthorized();
  }
  
  var self = this;
  this._validate(req.auth.userid, req.auth.password, function(err, user) {
    if (err || !user) { return self.unauthorized(); }
    self.success(user);
  });
}


/**
 * Expose `BasicStrategy`.
 */ 
module.exports = BasicStrategy;
