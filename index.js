const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const { Readable } = require('stream');
const x509parse = require('x509.js');

const port = 12345;
const host = '127.0.0.1';

const server = net.createServer({ allowHalfOpen: true });

let sockets = [];

const DELIMITER = '\n\n\n\n\n***************';

server.on('connection', (socket) => {
  let body = '';
  sockets.push(socket);
  console.log('CONNECTED: ' + socket.remoteAddress + ':' + socket.remotePort);
  socket.write('CONNECTED: ' + socket.remoteAddress + DELIMITER);

  socket.on('data', (data) => {
    body += data;
  });

  socket.on('end', () => {
    console.log(socket.bytesRead);
    const result = body.toString('binary').split(DELIMITER);

    const file1bytes = Number(result[0]);
    const file1Name = result[1];
    const file2bytes = Number(result[2]);
    const file2Name = result[3];
    const buffer1 = Buffer.alloc(file1bytes, Buffer.from(result[4], 'binary'));
    const buffer2 = Buffer.alloc(file2bytes, Buffer.from(result[5], 'binary'));
    fs.writeFileSync('./' + file1Name, buffer1);
    fs.writeFileSync('./' + file2Name, buffer2);

    const hash = crypto.createHash('sha512');
    const document = fs.readFileSync('./' + file2Name);
    hash.update(document);
    const publicKey = crypto.createPublicKey(
      fs.readFileSync('./public_key.pem')
    );
    const signature = fs.readFileSync('./signature.bin');
    const certificate = fs.readFileSync('./my-certificate.cert');
    const x509 = new crypto.X509Certificate(certificate);
    const parsedCertificate = x509parse.parseCert(certificate);
    const author =
      '\n\n****************************************\n\n' +
      'Author details:\n\n' +
      'Organization name: ' +
      parsedCertificate.issuer.organizationName +
      '\n' +
      'Common name: ' +
      parsedCertificate.issuer.commonName +
      '\n' +
      'Country: ' +
      parsedCertificate.issuer.countryName +
      '\n' +
      'City: ' +
      parsedCertificate.issuer.localityName;

    const res = crypto.publicDecrypt(
      publicKey,
      Buffer.from(signature, 'binary')
    );
    const resFile = 'verification-result.txt';
    socket.write(
      Buffer.from('sending Verification Result' + DELIMITER),
      'binary'
    );
    if (res.compare(hash.digest()) == 0 && x509.verify(publicKey)) {
      const buffer = Buffer.from('Signature is VALID.' + author);
      socket.write(Buffer.from(buffer.byteLength + DELIMITER), 'binary');
      socket.write(Buffer.from(resFile + DELIMITER), 'binary');
      Readable.from(buffer).pipe(socket);
    } else {
      fs.writeFileSync(resFile, 'Signature is NOT VALID.');
      socket.write(
        Buffer.from(fs.statSync('./' + resFile).size + DELIMITER),
        'binary'
      );
      socket.write(Buffer.from(resFile + DELIMITER), 'binary');
      const streamVerification = fs.createReadStream('./' + resFile);
      streamVerification.on('open', () => streamVerification.pipe(socket));
    }

    disconnect(socket);
  });
});

server.listen(port, host, () => {
  console.log('TCP Server is running on port ' + port + '.');
});

function disconnect(socket) {
  let index = sockets.findIndex(function (o) {
    return (
      o.remoteAddress === socket.remoteAddress &&
      o.remotePort === socket.remotePort
    );
  });
  if (index !== -1) sockets.splice(index, 1);
  console.log('CLOSED: ' + socket.remoteAddress + ' ' + socket.remotePort);
}
