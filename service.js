const fs = require('fs');
const util = require('util');
const crypto = require('crypto');
const { Readable } = require('stream');
const { Socket } = require('net');
const http = require('http');
const x509parse = require('x509.js');
const MultiStream = require('multistream');

const RECEIVED_ROOT = './_RECEIVED/';
const SIGNATURE_FILENAME_APPEND = '_signature.bin';
const VERIFICATION_RESULT_FILENAME = 'verification-result.txt';

module.exports = {
  processRequest: processRequest,
  processResponse: processResponse,
};

/**
 * Request Header:
 * 1. Signature bytes - UInt16(1) - 2 bytes - offset 0
 * 2. Document bytes - UInt32(1) - 4 bytes - offset 2
 * 3. Document filename bytes - UInt16(1) - 2 bytes - offset 6
 * 4. JWT bytes - UInt16(1) - 2 bytes - offset 8
 *
 * Request Payload (streams):
 * 5. Document filename
 * 6. Signature
 * 7. Document
 * 8. JWT
 * @param {Buffer[]} body
 * @returns jwt, documentFilename
 */
function parseRequest(body) {
  const received = Buffer.concat(body);

  const signatureBytesOffset = 0;
  const documentBytesOffset = 2;
  const documentFilenameBytesOffset = 6;
  const jwtBytesOffset = 8;
  const documentFilenameOffset = 10;

  const signatureBytes = received.readUInt16LE(signatureBytesOffset);
  const documentBytes = received.readUInt32LE(documentBytesOffset);
  const documentFilenameBytes = received.readUInt16LE(
    documentFilenameBytesOffset
  );
  const jwtBytes = received.readUInt16LE(jwtBytesOffset);

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
    documentFilenameOffset + documentFilenameBytes + signatureBytes,
    documentFilenameOffset +
      documentFilenameBytes +
      signatureBytes +
      documentBytes
  );
  const jwt = received
    .slice(
      documentFilenameOffset +
        documentFilenameBytes +
        signatureBytes +
        documentBytes
    )
    .toString();

  // Write document and signature to files -- for demonstration purposes!
  fs.writeFileSync(
    RECEIVED_ROOT + documentFilename + SIGNATURE_FILENAME_APPEND,
    signature
  );
  fs.writeFileSync(RECEIVED_ROOT + documentFilename, document);

  return { jwt, documentFilename };
}

/**
 * Gets client's certificate from REST service and verifies document signature
 * @param {Socket} socket
 * @param {Buffer[]} body
 * @param {Function} callback processResponse
 */
function processRequest(socket, body, callback) {
  const { jwt, documentFilename } = parseRequest(body);

  const options = {
    host: 'localhost',
    port: 8080,
    path: '/certificate',
    headers: { 'x-access-token': jwt },
  };

  http
    .request(options, (res) => {
      let data = '';

      res.on('data', (chunk) => (data += chunk));

      res.on('end', () => {
        const certificate = data.replace(/\\n/g, '\r\n').replace(/"/g, '');
        const x509 = new crypto.X509Certificate(certificate);
        const authorDetails = getCertificateAuthorDetails(certificate);

        if (verifySignature(documentFilename, x509)) {
          fs.writeFileSync(
            VERIFICATION_RESULT_FILENAME,
            'Signature is VALID.' + authorDetails
          );
        } else {
          fs.writeFileSync(
            VERIFICATION_RESULT_FILENAME,
            'Signature is NOT VALID.'
          );
        }

        callback(socket, certificate);
      });
    })
    .end();
}

function getCertificateAuthorDetails(certificate) {
  const parsedCertificate = x509parse.parseCert(certificate);

  return (
    '\n\n****************************************\n\n' +
    'Author details:\n\n' +
    'Organization name: ' +
    parsedCertificate.issuer.organizationName +
    '\n' +
    'Email/common name: ' +
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

  // Decrypt signature with author's public key obtained from certificate
  const signature = fs.readFileSync(
    RECEIVED_ROOT + documentFilename + SIGNATURE_FILENAME_APPEND
  );
  const decryptedSignature = crypto.publicDecrypt(x509.publicKey, signature);

  // Verify document hash equals decryped signature
  return decryptedSignature.compare(hash.digest()) == 0;
}

/**
 * Steps:
 * 1. Generate AES-128 key
 * 2. Export AES-128 key
 * 3. Create IV (randomBytes(16))
 * 4. Create cipher with AES-128 key+IV
 * 5. encryptedMessage = cipher.update(message)
 * 6. cipher.final()
 * 7. Get authTag from finalized cipher
 * 8. Get public key from certificate
 * 9. Encrypt AES-128 key with public key
 * 10. Send to client: encryptedMessage, authTag, encrypted AES-128 key, IV
 * @param {Socket} socket
 * @param {string} certificate
 */
function processResponse(socket, certificate) {
  util
    .promisify(crypto.generateKey)('aes', { length: 128 })
    .then((aesKey) => {
      const iv = crypto.randomBytes(16);

      const cipher = crypto.createCipheriv('aes-128-gcm', aesKey, iv);
      const encryptedMessage = cipher.update(
        fs.readFileSync(VERIFICATION_RESULT_FILENAME)
      );
      cipher.final();
      const authTag = cipher.getAuthTag();

      const x509 = new crypto.X509Certificate(certificate);

      const aesKeyEncrypted = crypto.publicEncrypt(
        x509.publicKey,
        aesKey.export()
      );

      writeHeader(
        socket,
        createHeader(encryptedMessage, aesKeyEncrypted, authTag, iv)
      );
      writePayload(
        socket,
        createPayload(encryptedMessage, aesKeyEncrypted, authTag, iv)
      );
    });
}

/**
 * Response Header:
 * 1. Encrypted message bytes - UInt8(1)
 * 2. Encrypted AES key bytes - UInt16(1)
 * 3. authTag bytes - UInt8(1)
 * 4. IV bytes - UInt8(1)
 * @param {Buffer} encyptedMessage
 * @param {Buffer} encryptedAesKey
 * @param {Buffer} authTag
 * @param {Buffer} iv
 * @returns encryptedMessageBytes, encryptedAesKeyBytes, authTagBytes, ivBytes
 */
function createHeader(encyptedMessage, encryptedAesKey, authTag, iv) {
  const encryptedMessageBytes = Buffer.alloc(1);
  encryptedMessageBytes.writeUInt8(encyptedMessage.byteLength);
  const encryptedAesKeyBytes = Buffer.alloc(2);
  encryptedAesKeyBytes.writeUInt16LE(encryptedAesKey.byteLength);
  const authTagBytes = Buffer.alloc(1);
  authTagBytes.writeUInt8(authTag.byteLength);
  const ivBytes = Buffer.alloc(1);
  ivBytes.writeUInt8(iv.byteLength);

  return { encryptedMessageBytes, encryptedAesKeyBytes, authTagBytes, ivBytes };
}

/**
 * Response Payload (streams):
 * 5. Encrypted message
 * 6. Encrypted AES key
 * 7. authTag
 * 8. IV
 * @param {Buffer} encyptedMessage
 * @param {Buffer} encryptedAesKey
 * @param {Buffer} authTag
 * @param {Buffer} iv
 * @returns streams: [encryptedMessageStream, encryptedAesKeyStream, authTagStream, ivStream]
 */
function createPayload(encyptedMessage, encryptedAesKey, authTag, iv) {
  const encryptedMessageStream = Readable.from(encyptedMessage);
  const encryptedAesKeyStream = Readable.from(encryptedAesKey);
  const authTagStream = Readable.from(authTag);
  const ivStream = Readable.from(iv);

  return {
    streams: [
      encryptedMessageStream,
      encryptedAesKeyStream,
      authTagStream,
      ivStream,
    ],
  };
}

function writeHeader(socket, header) {
  socket.write(header.encryptedMessageBytes);
  socket.write(header.encryptedAesKeyBytes);
  socket.write(header.authTagBytes);
  socket.write(header.ivBytes);
}

function writePayload(socket, payload) {
  new MultiStream(payload.streams).pipe(socket);
}
