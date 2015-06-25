var sinon = require ('sinon'),
  chai = require ('chai'),
  sinonChai = require('sinon-chai'),
  utils = require('chai/lib/chai/utils');

chai.use(sinonChai);

global.expect = chai.expect;

beforeEach(function(){
  global.sinon = sinon.sandbox.create();
});

afterEach(function(){
  global.sinon.restore();
});

utils.addMethod(chai.Assertion.prototype, 'apiError', function(errorIdObj) {
  var obj = utils.flag(this, 'object');
  new chai.Assertion(obj).to.exist;
  new chai.Assertion(obj.namespace).to.be.equal(errorIdObj.namespace);
  new chai.Assertion(obj.name).to.be.equal(errorIdObj.name);
});
