const net = require('net');
const fs = require('fs');
const crypto = require('crypto');

const port = 12345;
const host = '127.0.0.1';

const server = net.createServer();
server.listen(port, host, () => {
  console.log('TCP Server is running on port ' + port + '.');
});

let sockets = [];

server.on('connection', function (sock) {
  console.log('CONNECTED: ' + sock.remoteAddress + ':' + sock.remotePort);
  sockets.push(sock);
  sock.write('CONNECTED: ' + sock.remoteAddress);

  sock.on('data', function (data) {
    if (data.toString() == 'sendingPublicKey') {
      sock.write('receivingPublicKey');
      sock.pipe(fs.createWriteStream('./public_key.pem'));
      sock.write('receivedPublicKey');
    }
    if (data.toString() == 'sendingSignature') {
      sock.write('receivingSignature');
      sock.pipe(fs.createWriteStream('./signature.bin'));
      sock.write('receivedSignature');
    }
    if (data.toString() == 'sendingDocument') {
      sock.write('receivingDocument');
      sock.pipe(fs.createWriteStream('./document'));
      // const fileStream = fs.createWriteStream('./document');
      // fileStream.on('ready', () => sock.pipe(fileStream));
      sock.write('receivedDocument');
    }
    if (data.toString() == 'verifySignature') {
      const document = fs.readFileSync('./document');
      const hash = crypto.createHash('sha256');
      hash.update(document);
      const publicKey = crypto.createPublicKey(
        fs.readFileSync('./public_key.pem')
      );
      const signature = fs.readFileSync('./signature.bin');

      const result = crypto.publicDecrypt(publicKey, signature);
      if (result.compare(hash.digest()) == 0) {
        sock.write('valid');
        console.log('valid');
      } else {
        sock.write('invalid');
        console.log('invalid');
      }
      sock.destroy();
    }
  });

  // Add a 'close' event handler to this instance of socket
  sock.on('close', function (data) {
    // let index = sockets.findIndex(function (o) {
    //   return (
    //     o.remoteAddress === sock.remoteAddress &&
    //     o.remotePort === sock.remotePort
    //   );
    // });
    // if (index !== -1) sockets.splice(index, 1);
    console.log('CLOSED: ' + sock.remoteAddress + ' ' + sock.remotePort);
  });
});
