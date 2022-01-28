const net = require('net');
const service = require('./service');

const port = 12345,
  host = '127.0.0.1',
  server = net.createServer({ allowHalfOpen: true });

let sockets = [];

server
  .on('connection', (socket) => {
    console.log(`CONNECTED: ${socket.remoteAddress}:${socket.remotePort}`);
    sockets.push(socket);

    const requestBody = [];
    socket.on('data', (data) => {
      requestBody.push(data);
    });

    socket.on('end', () => {
      service.processRequest(socket, requestBody);
      disconnect(socket);
    });
  })
  .listen(port, host, () => {
    console.log(`TCP Server is running on port ${port}.`);
  });

function disconnect(socket) {
  const index = sockets.findIndex(
    (o) =>
      o.remoteAddress === socket.remoteAddress &&
      o.remotePort === socket.remotePort
  );

  if (index !== -1) sockets.splice(index, 1);
  console.log(`CLOSED: ${socket.remoteAddress}:${socket.remotePort}`);
}
