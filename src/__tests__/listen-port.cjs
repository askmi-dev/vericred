const net = require('node:net');
const listen = net.Server.prototype.listen;
net.Server.prototype.listen = function (...args) {
  this.once('listening', () => process.send?.({ port: this.address().port }));
  return listen.apply(this, args);
};

require('node:module').registerHooks({
  load(url, context, nextLoad) {
    if (/\/oid4vp\/router\.(ts|js)$/.test(url)) {
      process.stderr.write('[test] verifier module loaded\n');
    }
    return nextLoad(url, context);
  },
});
