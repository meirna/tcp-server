const net = require('net');
const fs = require('fs');
const crypto = require('crypto');

const port = 12345;
const host = '127.0.0.1';

const server = net.createServer();

let sockets = [];

server.on('connection', function (socket) {
  let body = '';
  sockets.push(socket);
  console.log('CONNECTED: ' + socket.remoteAddress + ':' + socket.remotePort);
  socket.write('CONNECTED: ' + socket.remoteAddress);

  socket.on('data', (data) => {
    body += data;
  });

  // Add a 'close' event handler to this instance of socket
  socket.on('close', function (data) {
    const result = [...body.toString().split('\n\n\n\n')];

    const file1bytes = parseInt(result[0]);
    const file1Name = result[1];
    const buffer1 = Buffer.alloc(file1bytes, result[2], 'binary');
    fs.writeFileSync('./' + file1Name, buffer1);
    const file2bytes = parseInt(result[3]);
    const file2Name = result[4];
    const buffer2 = Buffer.alloc(file2bytes, result[5], 'binary');
    fs.writeFileSync('./' + file2Name, buffer2);

    const hash = crypto.createHash('sha512');
    const document = fs.readFileSync('./' + file1Name);
    hash.update(document);
    const publicKey = crypto.createPublicKey(
      fs.readFileSync('./public_key.pem')
    );
    const signature = fs.readFileSync('./signature.bin');
    const certificate = fs.readFileSync('./my-certificate.cert');
    const x509 = new crypto.X509Certificate(certificate);

    const res = crypto.publicDecrypt(publicKey, signature);

    if (res.compare(hash.digest()) == 0 && x509.verify(publicKey)) {
      socket.write('valid');
      console.log('valid');
      // console.log(x509.subject);
    } else {
      socket.write('invalid');
      console.log('invalid');
      // console.log(x509.subject);
    }

    let index = sockets.findIndex(function (o) {
      return (
        o.remoteAddress === socket.remoteAddress &&
        o.remotePort === socket.remotePort
      );
    });
    if (index !== -1) sockets.splice(index, 1);
    console.log('CLOSED: ' + socket.remoteAddress + ' ' + socket.remotePort);
  });
});

server.listen(port, host, () => {
  console.log('TCP Server is running on port ' + port + '.');
});
