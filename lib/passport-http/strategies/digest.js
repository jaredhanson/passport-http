/**
 * Module dependencies.
 */
var passport = require('passport')
  , crypto = require('crypto')
  , util = require('util');


/**
 * `DigestStrategy` constructor.
 */
function DigestStrategy(options, secret, validate) {
  if (typeof options == 'function') {
    validate = secret;
    secret = options;
    options = {};
  }
  if (!secret) throw new Error('HTTP Digest authentication strategy requires a secret function');
  if (!validate) throw new Error('HTTP Digest authentication strategy requires a validate function');
  
  passport.Strategy.call(this);
  this.name = 'digest';
  this.secret = secret;
  this.validate = validate;
  this._realm = options.realm || 'Users';
  if (options.domain) {
    this._domain = (Array.isArray(options.domain)) ? options.domain : [ options.domain ]
  }
  this._opaque = options.opaque;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(DigestStrategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a HTTP Digest authorization
 * header.
 *
 * @param {Object} req
 * @api protected
 */
DigestStrategy.prototype.authenticate = function(req) {
  var authorization = req.headers['authorization'];
  if (!authorization) { return this.fail(this._challenge()); }
  
  var parts = authorization.split(' ')
  if (parts.length < 2) { return this.fail(this._challenge()); }
  
  var scheme = parts[0]
    , params = parts.slice(1).join(' ');
  
  if (!/Digest/i.test(scheme)) { return this.fail(this._challenge()); }
  
  var creds = parse(params);
  
  //console.log('CREDENTIALS: ' + util.inspect(creds));
  
  var self = this;
  
  // Use of digest authentication requires a password (aka shared secret) known
  // to both the client and server, but not transported over the wire.  This
  // secret is needed in order to compute the hashes required to authenticate
  // the request, and can be obtained by calling the secret() function the
  // application provides to the strategy.
  this.secret(creds.username, function(err, password) {
    if (err) { return self.error(err); }
    if (!password) { return self.fail(self._challenge()); }
    
    var ha1 = md5(creds.username + ":" + creds.realm + ":" + password);
    var ha2 = md5(req.method + ":" + creds.uri);
    var digest = md5(ha1 + ":" + creds.nonce + ":" + ha2);
    
    //console.log('DIGEST: ' + digest);
    
    if (creds.response != digest) {
      return self.fail(self._challenge());
    } else {
      // TODO: Determine the proper signature for validate callback
      self.validate(creds.username, {}, function(err, user) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(self._challenge()); }
        self.success(user);
      });
    }
  });
}

/**
 * Authentication challenge.
 *
 * @api private
 */
DigestStrategy.prototype._challenge = function() {
  var challenge = 'Digest realm="' + this._realm + '"';
  if (this._domain) {
    challenge += ', domain="' + this._domain.join(' ') + '"';
  }
  challenge += ', nonce="' + nonce(32) + '"';
  if (this._opaque) {
    challenge += ', opaque="' + this._opaque + '"';
  }
  
  return challenge;
}


function parse(params) {
  //console.log('parse()');
  //console.log('  params: ' + params);
  
  // TODO: allow for unquoted strings
  
  var opts = {};
  var tokens = params.match(/(\w+)="([^"]+)"/g);
  if (tokens) {
    for (var i = 0, len = tokens.length; i < len; i++) {
      var param = /(\w+)="([^"]+)"/.exec(tokens[i])
      opts[param[1]] = param[2];
    }
  }
  return opts;
}

/**
 * CREDIT: Connect -- utils.uid
 *         https://github.com/senchalabs/connect/blob/1.7.1/lib/utils.js
 *
 * @api private
 */
function nonce(len) {
  var buf = []
    , chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    , charlen = chars.length;

  for (var i = 0; i < len; ++i) {
    buf.push(chars[Math.random() * charlen | 0]);
  }

  return buf.join('');
};


/**
 * CREDIT: Connect -- utils.md5
 *         https://github.com/senchalabs/connect/blob/1.7.1/lib/utils.js
 *
 * @api private
 */
function md5(str, encoding){
  return crypto
    .createHash('md5')
    .update(str)
    .digest(encoding || 'hex');
};


/**
 * Expose `DigestStrategy`.
 */ 
module.exports = DigestStrategy;
