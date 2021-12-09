const net = require('net');
const service = require('./service');

const port = 12345;
const host = '127.0.0.1';

const server = net.createServer({ allowHalfOpen: true });

let sockets = [];

server.on('connection', (socket) => {
  let body = '';
  sockets.push(socket);
  console.log('CONNECTED: ' + socket.remoteAddress + ':' + socket.remotePort);
  socket.write('CONNECTED: ' + socket.remoteAddress + service.delimiter);

  socket.on('data', (data) => {
    body += data;
  });

  socket.on('end', () => {
    service.processRequest(socket, body);

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
