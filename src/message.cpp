#include "message.h"

Message::Message() : _data(), _readPos(), _writePos()
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

	return std::make_unique<Message>(data.copyToVector(HeaderSize, messageLength));
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

const Message& Message::operator>>(std::string& str) const
{
	str.clear();

	char c;
	while ((c = read<char>()) != '\0')
		str += c;

	return *this;
}

const Message& Message::operator>>(boost::dynamic_bitset<std::uint64_t>& bitset) const
{
	bitset = boost::dynamic_bitset<std::uint64_t>(read<std::string>());
	return *this;
}

Message& Message::operator<<(const std::string& str)
{
	for (auto itr = str.begin(); itr != str.end(); ++itr)
		write<char>(*itr);

	write<char>('\0');
	return *this;
}

Message& Message::operator<<(const boost::dynamic_bitset<std::uint64_t>& bitset)
{
	std::string bitsetStr;
	boost::to_string(bitset, bitsetStr);
	write(bitsetStr);
	return *this;
}
