var vows = require('vows');
var assert = require('assert');
var util = require('util');
var http = require('passport-http');


vows.describe('passport-http').addBatch({
  
  'module': {
    'should export BasicStrategy': function (x) {
      assert.isFunction(http.BasicStrategy);
    },

    'should export DigestStrategy': function (x) {
      assert.isFunction(http.DigestStrategy);
    }
  },
  
}).export(module);
