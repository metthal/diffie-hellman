#pragma once

#include <array>
#include <deque>
#include <memory>
#include <string>

#include <boost/asio.hpp>

#include "error.h"
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

class Service
{
public:
	Service(const std::string& socketPath);

	virtual void start() = 0;

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

				_messageQueue.push_back(std::move(message));
			}

			retryReceive = _messageQueue.empty();
		}

		auto message = std::move(_messageQueue.front());
		_messageQueue.pop_front();

		return fn(static_cast<const Message*>(message.get()));
	}

	void sendMessage(const Message& message)
	{
		boost::system::error_code errorCode;
		auto msgBuffer = message.serialize();
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
	}

	template <typename... Ts>
	void send(Ts&&... args)
	{
		Message msg;
		sendImpl(msg, std::forward<Ts>(args)...);
		sendMessage(msg);
	}

protected:
	void sendImpl(Message&) {}

	template <typename T, typename... Ts>
	void sendImpl(Message& msg, T&& arg, Ts&&... args)
	{
		msg.write<T>(std::forward<T>(arg));
		sendImpl(msg, std::forward<Ts>(args)...);
	}

	boost::asio::io_service _ioService;
	boost::asio::local::stream_protocol::endpoint _localEndpoint;
	boost::asio::local::stream_protocol::socket _socket;
	std::vector<std::uint8_t> _recvBuffer;
	std::size_t _recvdBytes;
	std::deque<std::unique_ptr<Message>> _messageQueue;
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
