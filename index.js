const net = require('net');
const service = require('./service');

const port = 12345;
const host = '127.0.0.1';

const server = net.createServer();

let sockets = [];

server.on('connection', (socket) => {
  const requestBody = [];

  sockets.push(socket);
  console.log('CONNECTED: ' + socket.remoteAddress + ':' + socket.remotePort);

  socket.on('data', (data) => {
    requestBody.push(data);
  });

  socket.on('end', () => {
    service.processRequest(requestBody);

    // service.sendResponse(socket);

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
