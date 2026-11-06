import { Server } from 'node:net';
import { register } from 'node:module';

const listen = Server.prototype.listen;
Server.prototype.listen = function (...args) {
  this.once('listening', () => process.send?.({ port: this.address().port }));
  return listen.apply(this, args);
};

// Match tsx's asynchronous loader chain on Node 22. Mixing registerHooks()
// (synchronous) with tsx's asynchronous hooks fails before server startup.
register('./observe-verifier.mjs', import.meta.url);
