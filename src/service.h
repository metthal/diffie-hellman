#pragma once

#include <array>
#include <deque>
#include <memory>
#include <string>
#include <iostream>

#include <boost/asio.hpp>

#include "cipher_engine.h"
#include "error.h"
#include "hash.h"
#include "message.h"
#include "span.h"

class ConnectionClosedError : public Error
{
public:
	ConnectionClosedError() noexcept : Error("Connection closed by remote host.") {}
};

class ConnectionFailureError : public Error
{
public:
	ConnectionFailureError() noexcept : Error("Connection failure.") {}
};

class UnableToConnectError : public Error
{
public:
	UnableToConnectError() noexcept : Error("Unable to connect to server.") {}
};

class Service
{
public:
	Service(const std::string& socketPath);

	virtual void start() = 0;

	template <Cipher C, HashAlgo Hash>
	void createSecuredChannel(const BigInt& generator, const BigInt& modulus)
	{
		// Calculate secret exponent E and public key G^E mod P
		auto secretExp = BigInt::random(modulus.getNumberOfBits() - 1);
		auto publicKey = generator.raiseMod(secretExp, modulus);

		// Send public key and receive public key from the other side
		send(publicKey);
		auto otherSidePublicKey = receive(
				[&](const Message* msg) {
					return msg->read<BigInt>();
				}
			);

		// Calculate shared secret and derive key from it using hash function
		auto sharedSecret = otherSidePublicKey.raiseMod(secretExp, modulus);
		auto key = hash<Hash>(sharedSecret.getRawBytes());

		// From now on, all communication is encrypted
		setCipher<C>(key);
	}

	void authenticate(const BigInt& modulus, const std::vector<BigInt>& privateKey);
	bool verifyAuthentication(const BigInt& modulus, std::size_t keyElementCount);

	template <typename Fn>
	decltype(auto) receive(Fn&& fn)
	{
		boost::system::error_code errorCode;
		bool retryReceive = _messageQueue.empty();
		while (retryReceive)
		{
			_recvdBytes += _socket.read_some(
					boost::asio::buffer(
						_recvBuffer.data() + _recvdBytes,
						_recvBuffer.size() - _recvdBytes
					),
					errorCode
				);

			if (errorCode)
			{
				if (errorCode != boost::asio::error::eof)
					throw ConnectionFailureError();
				else if (_recvdBytes == 0)
					throw ConnectionClosedError();
			}

			std::unique_ptr<Message> message;
			while ((message = Message::parse(makeSpan(_recvBuffer.data(), _recvdBytes))) != nullptr)
			{
				std::size_t newRecvdBytes = _recvdBytes - message->getTotalSize(); // calculate size of rest of the data in the recv. buffer
				std::memmove(_recvBuffer.data(), _recvBuffer.data() + message->getTotalSize(), newRecvdBytes); // shift recv. buffer to the left by the size of recently parsed message
				std::memset(_recvBuffer.data() + newRecvdBytes, 0, _recvdBytes - newRecvdBytes); // nullify the trailer part of the shifted content (this is just for security reasons)
				_recvdBytes = newRecvdBytes; // updated the size of the recv. buffer

				if (_cipherEngine != nullptr)
				{
					auto encryptedMsg = message->read<EncryptedData>();
					auto decryptedMsg = _cipherEngine->decrypt(encryptedMsg);
					message = std::make_unique<Message>(decryptedMsg);
				}

				_messageQueue.push_back(std::move(message));
			}

			retryReceive = _messageQueue.empty();
		}

		auto message = std::move(_messageQueue.front());
		_messageQueue.pop_front();

		return fn(static_cast<const Message*>(message.get()));
	}

	Message sendMessage(const Message& message)
	{
		auto transmittedMsg = message;
		if (_cipherEngine != nullptr)
		{
			transmittedMsg = {};
			transmittedMsg.write<EncryptedData>(_cipherEngine->encrypt(message));
		}

		boost::system::error_code errorCode;
		auto msgBuffer = transmittedMsg.serialize();
		std::size_t sentBytes = 0;

		while (sentBytes < msgBuffer.size())
		{
			sentBytes += _socket.write_some(
					boost::asio::buffer(
						msgBuffer.data() + sentBytes,
						msgBuffer.size() - sentBytes
					),
					errorCode
				);

			if (errorCode)
				throw ConnectionFailureError();
		}

		return message;
	}

	template <typename... Ts>
	Message send(Ts&&... args)
	{
		Message msg;
		sendImpl(msg, std::forward<Ts>(args)...);
		return sendMessage(msg);
	}

	template <Cipher C>
	void setCipher(const BigInt& key)
	{
		_cipherEngine = std::make_unique<CipherEngine<C>>(key);
	}

	void removeCipher();

protected:
	void sendImpl(Message&) {}

	template <typename T, typename... Ts>
	void sendImpl(Message& msg, T&& arg, Ts&&... args)
	{
		msg.write(std::forward<T>(arg));
		sendImpl(msg, std::forward<Ts>(args)...);
	}

	boost::asio::io_service _ioService;
	boost::asio::local::stream_protocol::endpoint _localEndpoint;
	boost::asio::local::stream_protocol::socket _socket;
	std::vector<std::uint8_t> _recvBuffer;
	std::size_t _recvdBytes;
	std::deque<std::unique_ptr<Message>> _messageQueue;
	std::unique_ptr<CipherEngineBase> _cipherEngine;
};

class Server : public Service
{
public:
	Server(const std::string& socketPath);

	virtual void start() override;
};

class Client : public Service
{
public:
	Client(const std::string& socketPath);

	virtual void start() override;
};
