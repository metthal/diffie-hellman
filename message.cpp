#include "message.h"

Message::Message() : _data(), _readPos(0), _writePos(0)
{
}

Message::Message(const std::vector<std::uint8_t>& data) : _data(data), _readPos(0), _writePos(0)
{
}

Message::Message(std::vector<std::uint8_t>&& data) : _data(std::move(data)), _readPos(0), _writePos(0)
{
}

std::unique_ptr<Message> Message::parse(const Span<std::uint8_t>& data)
{
	if (data.getSize() <= HeaderSize)
		return nullptr;

	Message headerMessage(data.copyToVector(0, HeaderSize));
	auto messageLength = headerMessage.read<std::uint16_t>();
	if (messageLength > data.getSize() - HeaderSize)
		return nullptr;

	return std::make_unique<Message>(data.copyToVector(HeaderSize));
}

std::size_t Message::getTotalSize() const
{
	return HeaderSize + _data.size();
}

const std::vector<std::uint8_t>& Message::getContent() const
{
	return _data;
}

std::vector<std::uint8_t> Message::serialize() const
{
	Message headerMsg;
	headerMsg.write<std::uint16_t>(_data.size());

	std::vector<std::uint8_t> result(HeaderSize + _data.size());
	std::copy(headerMsg.getContent().begin(), headerMsg.getContent().end(), result.begin());
	std::copy(_data.begin(), _data.end(), result.begin() + HeaderSize);

	return result;
}
