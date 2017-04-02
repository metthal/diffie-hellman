#include <unistd.h>

#include "service.h"

namespace {

const std::size_t DefaultBufferSize = 4096;

}

Service::Service(const std::string& socketPath) : _ioService(), _localEndpoint(socketPath), _socket(_ioService),
	_recvBuffer(DefaultBufferSize), _recvdBytes(0), _messageQueue()
{
}

Server::Server(const std::string& socketPath) : Service(socketPath)
{
}

void Server::start()
{
	unlink(_localEndpoint.path().c_str());

	boost::asio::local::stream_protocol::acceptor acceptor(_ioService, _localEndpoint);
	acceptor.accept(_socket);
}

Client::Client(const std::string& socketPath) : Service(socketPath)
{
}

void Client::start()
{
	_socket.connect(_localEndpoint);
}
