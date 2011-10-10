module.exports = function basic() {
  
  return function basic(req, res, next) {
    var authorization = req.headers['authorization'];
    if (!authorization) { return next(); }
    
    var parts = authorization.split(' ')
      , scheme = parts[0]
      , credentials = new Buffer(parts[1], 'base64').toString().split(':');

    if ('Basic' != scheme) { return next(); }
    
    req.auth = req.auth || {};
    req.auth.userid = credentials[0];
    req.auth.password = credentials[1];
    next();
  }
}
