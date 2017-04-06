#include <unistd.h>

#include "service.h"
#include "utils.h"

namespace {

const std::size_t DefaultBufferSize = 4096;

}

Service::Service(const std::string& socketPath) : _ioService(), _localEndpoint(socketPath), _socket(_ioService),
	_recvBuffer(DefaultBufferSize), _recvdBytes(0), _messageQueue(), _cipherEngine()
{
}

void Service::authenticate(const BigInt& modulus, const std::vector<BigInt>& privateKey)
{
	// Calculate public key vector and send it to the server
	auto signs = randomBits(privateKey.size());
	std::size_t bitCounter = 0;
	std::for_each(privateKey.begin(), privateKey.end(),
			[&, this](const auto& s) {
				auto sSqInv = s.raiseMod(2, modulus).invertMod(modulus);
				this->send(signs[bitCounter++] ? -sSqInv : sSqInv);
			});

	// Calculate witness and send it to the server
	auto secretR = BigInt::random(modulus.getNumberOfBits() - 1);
	auto witness = secretR.raiseMod(2, modulus);
	send(randomBits(1)[0] ? -witness : witness);

	// Receive bit vector from server
	auto usedKeyElements = receive(
			[&](const Message* msg) {
				return msg->read<boost::dynamic_bitset<std::uint64_t>>();
			}
		);

	// Calculate evidence
	auto evidence = secretR;
	for (std::size_t i = 0; i < usedKeyElements.size(); ++i)
	{
		if (!usedKeyElements[i])
			continue;

		evidence = (evidence * privateKey[i]) % modulus;
	}
	send(evidence);
}

bool Service::verifyAuthentication(const BigInt& modulus, std::size_t keyElementCount)
{
	// Receive public key vector from the client
	std::vector<BigInt> ffsV;
	for (std::size_t i = 0; i < keyElementCount; ++i)
	{
		receive([&](const Message* msg) {
					ffsV.push_back(msg->read<BigInt>());
				}
			);
	}

	// Receive witness from client
	auto witness = receive(
			[&](const Message* msg) {
				return msg->read<BigInt>();
			}
		);

	// Generate bit vector for proof calculation
	auto usedKeyElements = randomBits(keyElementCount);
	send(usedKeyElements);

	// Receive evidence
	auto evidence = receive(
			[&](const Message* msg) {
				return msg->read<BigInt>();
			}
		);

	auto finalValue = evidence.raiseMod(2, modulus);
	for (std::size_t i = 0; i < usedKeyElements.size(); ++i)
	{
		if (!usedKeyElements[i])
			continue;

		finalValue = (finalValue * ffsV[i]) % modulus;
	}

	return witness != 0 && (finalValue == witness || finalValue == -witness);
}

void Service::removeCipher()
{
	_cipherEngine.reset(nullptr);
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
	boost::system::error_code errorCode;
	_socket.connect(_localEndpoint, errorCode);

	if (errorCode)
		throw UnableToConnectError();
}
