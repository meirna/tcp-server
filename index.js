const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const { Readable } = require('stream');
const x509parse = require('x509.js');

const port = 12345;
const host = '127.0.0.1';

const server = net.createServer({ allowHalfOpen: true });

let sockets = [];

const RESULT_FILENAME = 'verification-result.txt';
const CERTIFICATE_PATH = './my-certificate.cert';
const DELIMITER = '\n\n\n\n\n***************';
const RECEIVED_ROOT = './_RECEIVED/';

server.on('connection', (socket) => {
  let body = '';
  sockets.push(socket);
  console.log('CONNECTED: ' + socket.remoteAddress + ':' + socket.remotePort);
  socket.write('CONNECTED: ' + socket.remoteAddress + DELIMITER);

  socket.on('data', (data) => {
    body += data;
  });

  socket.on('end', () => {
    // Parse data received from client (document and signature)
    const result = body.toString('binary').split(DELIMITER);
    const signatureBytes = Number(result[0]);
    let signatureFilename = result[1];
    const documentBytes = Number(result[2]);
    const documentFilename = result[3];
    signatureFilename = documentFilename + '_' + signatureFilename;
    const signatureBuffer = Buffer.alloc(
      signatureBytes,
      Buffer.from(result[4], 'binary')
    );
    const documentBuffer = Buffer.alloc(
      documentBytes,
      Buffer.from(result[5], 'binary')
    );

    // Write document and signature to files
    fs.writeFileSync(RECEIVED_ROOT + signatureFilename, signatureBuffer);
    fs.writeFileSync(RECEIVED_ROOT + documentFilename, documentBuffer);

    // Calculate document hash
    const hash = crypto.createHash('sha512');
    const document = fs.readFileSync(RECEIVED_ROOT + documentFilename);
    hash.update(document);

    // Parse certificate to get author information
    const certificate = fs.readFileSync(CERTIFICATE_PATH);
    const x509 = new crypto.X509Certificate(certificate);
    const author = parseCertificate(certificate);

    // Compare document hash with decrypted signature & verify certificate matches public key, then stream result to client
    const publicKey = crypto.createPublicKey(
      fs.readFileSync('./public_key.pem')
    );
    const signature = fs.readFileSync(RECEIVED_ROOT + signatureFilename);
    const decryptedSignature = crypto.publicDecrypt(
      publicKey,
      Buffer.from(signature, 'binary')
    );
    socket.write(
      Buffer.from('sending Verification Result' + DELIMITER),
      'binary'
    );
    if (
      decryptedSignature.compare(hash.digest()) == 0 &&
      x509.verify(publicKey)
    ) {
      streamToClient(socket, 'Signature is VALID.' + author);
    } else {
      streamToClient(socket, 'Signature is NOT VALID.');
    }

    disconnect(socket);
  });
});

server.listen(port, host, () => {
  console.log('TCP Server is running on port ' + port + '.');
});

function parseCertificate(certificate) {
  const parsedCertificate = x509parse.parseCert(certificate);
  return (
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
    parsedCertificate.issuer.localityName
  );
}

function streamToClient(socket, data) {
  const buffer = Buffer.from(data);
  socket.write(Buffer.from(buffer.byteLength + DELIMITER), 'binary');
  socket.write(Buffer.from(RESULT_FILENAME + DELIMITER), 'binary');
  Readable.from(buffer).pipe(socket);
}

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
