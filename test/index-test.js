var vows = require('vows');
var assert = require('assert');
var util = require('util');
var http = require('passport-http');


vows.describe('passport-http').addBatch({
  
  'module': {
    'should report a version': function (x) {
      assert.isString(http.version);
    },
  },
  
}).export(module);
