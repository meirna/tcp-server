const fs = require('fs');
const crypto = require('crypto');
const { Readable, Writable } = require('stream');
const x509parse = require('x509.js');
const MultiStream = require('multistream');

const RECEIVED_ROOT = './_RECEIVED/';
const SIGNATURE_FILENAME_APPEND = '_signature.bin';
const VERIFICATION_RESULT_FILENAME = 'verification-result.txt';
const CIPHER_FILENAME = 'cipher.bin';
const CERTIFICATE_PATH = './my-certificate.cert';
const PUBLIC_KEY_PATH = './public_key.pem';

module.exports = {
  processRequest: processRequest,
  sendResponse: sendResponse,
};

function processRequest(body) {
  const documentFilename = parseRequest(body);

  // Parse author's certificate
  const certificate = fs.readFileSync(CERTIFICATE_PATH);
  const x509 = new crypto.X509Certificate(certificate);
  const authorDetails = getCertificateAuthorDetails(certificate);

  if (verifySignature(documentFilename, x509)) {
    fs.writeFileSync(
      VERIFICATION_RESULT_FILENAME,
      'Signature is VALID.' + authorDetails
    );
  } else {
    fs.writeFileSync(VERIFICATION_RESULT_FILENAME, 'Signature is NOT VALID.');
  }
}

function parseRequest(body) {
  const received = Buffer.concat(body);

  // HEADER:
  // 1. Signature bytes - UInt16Array(1) - 2 bytes - offset 0
  // 2. Document bytes - UInt32Array(1) - 4 bytes - offset 2
  // 3. Document filename bytes - UInt16Array(1) - 2 bytes - offset 6
  const signatureBytesOffset = 0;
  const documentBytesOffset = 2;
  const documentFilenameBytesOffset = 6;
  const documentFilenameOffset = 8;

  const signatureBytes = received.readUInt16LE(signatureBytesOffset);
  const documentBytes = received.readUInt32LE(documentBytesOffset);
  const documentFilenameBytes = received.readUInt16LE(
    documentFilenameBytesOffset
  );

  // PAYLOAD (streams):
  // 4. Document filename
  // 5. Signature
  // 6. Document
  const documentFilename = received
    .slice(
      documentFilenameOffset,
      documentFilenameOffset + documentFilenameBytes
    )
    .toString();
  const signature = received.slice(
    documentFilenameOffset + documentFilenameBytes,
    documentFilenameOffset + documentFilenameBytes + signatureBytes
  );
  const document = received.slice(
    documentFilenameOffset + documentFilenameBytes + signatureBytes
  );

  // Write document and signature to files -- for demonstration purposes!
  fs.writeFileSync(
    RECEIVED_ROOT + documentFilename + SIGNATURE_FILENAME_APPEND,
    signature
  );
  fs.writeFileSync(RECEIVED_ROOT + documentFilename, document);

  return documentFilename;
}

function getCertificateAuthorDetails(certificate) {
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

function verifySignature(documentFilename, x509) {
  // Calculate document hash
  const document = fs.readFileSync(RECEIVED_ROOT + documentFilename);
  const hash = crypto.createHash('sha512');
  hash.update(document);

  // Decrypt signature with author's public key
  const publicKey = crypto.createPublicKey(fs.readFileSync(PUBLIC_KEY_PATH));
  const signature = fs.readFileSync(
    RECEIVED_ROOT + documentFilename + SIGNATURE_FILENAME_APPEND
  );
  const decryptedSignature = crypto.publicDecrypt(publicKey, signature);

  // Verify document hash equals decryped signature &&
  // verify certificate contains author's public key
  return (
    decryptedSignature.compare(hash.digest()) == 0 && x509.verify(publicKey)
  );
}

function sendResponse(socket) {
  // Generate cipher (symmetric key)
  // const key = crypto.randomBytes(24);
  const initializationVector = crypto.randomBytes(64);
  // const cipher = crypto.createCipheriv(
  //   'aes-192-gcm',
  //   key,
  //   initializationVector
  // );

  const key = crypto.generateKeySync('aes', { length: 192 });
  const cipher = crypto.createCipheriv(
    'aes-192-gcm',
    key,
    initializationVector
  );

  // Encrypt message (verification result) with cipher
  const verificationResult = fs.readFileSync(VERIFICATION_RESULT_FILENAME);
  const encryptedVerificationResult = cipher.update(verificationResult);
  fs.writeFileSync(
    RECEIVED_ROOT + 'encryptedVerificationResult.bin',
    encryptedVerificationResult
  );

  // Encrypt cipher with client's public key
  const publicKey = crypto.createPublicKey(fs.readFileSync(PUBLIC_KEY_PATH));
  // const encryptedCipher = crypto.publicEncrypt(publicKey, cipher.final());
  const encryptedKey = crypto.publicEncrypt(publicKey, key.export());
  // fs.writeFileSync(RECEIVED_ROOT + 'encryptedCipher.bin', encryptedCipher);
  fs.writeFileSync(RECEIVED_ROOT + 'encryptedKey.bin', encryptedKey);

  // Send encrypted cipher and message (verification result) to client
  writeHeader(socket, createHeader(encryptedKey, encryptedVerificationResult));
  writePayload(
    socket,
    createPayload(encryptedKey, encryptedVerificationResult)
  );
}

function createHeader(encryptedKey, encryptedVerificationResult) {
  // HEADER:
  // 1. Encrypted cipher bytes - UInt16(1)
  // 2. Encrypted verification result bytes - UInt16(1)

  const cipherBytes = Buffer.alloc(2);
  cipherBytes.writeUInt16LE(encryptedKey.byteLength);
  const resultBytes = Buffer.alloc(2);
  resultBytes.writeUInt16LE(encryptedVerificationResult.byteLength);

  return { cipherBytes, resultBytes };
}

function createPayload(encryptedCipher, encryptedVerificationResult) {
  // PAYLOAD (streams):
  // 3. Encrypted cipher
  // 4. Encrypted verification result

  const cipherStream = Readable.from(encryptedCipher);
  const resultStream = Readable.from(encryptedVerificationResult);

  return { files: [cipherStream, resultStream] };
}

function writeHeader(socket, header) {
  socket.write(header.cipherBytes);
  socket.write(header.resultBytes);
}

function writePayload(socket, payload) {
  new MultiStream(payload.files).pipe(socket);
}
