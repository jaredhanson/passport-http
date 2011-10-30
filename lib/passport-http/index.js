/**
 * Module dependencies.
 */
var BasicStrategy = require('./strategies/basic');
var DigestStrategy = require('./strategies/digest');


/**
 * Framework version.
 */
exports.version = '0.1.1';

/**
 * Expose constructors.
 */
exports.BasicStrategy = BasicStrategy;
exports.DigestStrategy = DigestStrategy;
