#pragma once

#include <bitset>
#include <cstring>
#include <memory>
#include <type_traits>
#include <vector>

#include "big_int.h"
#include "error.h"
#include "hash.h"
#include "span.h"

class NotEnoughDataError : public Error
{
public:
	NotEnoughDataError() noexcept : Error("Not enough data in stream buffer.") {}
};

class SequenceTooLongError : public Error
{
public:
	SequenceTooLongError() noexcept : Error("Sequence is too long.") {}
};

class Message
{
public:
	constexpr static const std::size_t HeaderSize = sizeof(std::uint16_t);

	Message();
	Message(const std::vector<std::uint8_t>& data);
	Message(std::vector<std::uint8_t>&& data);
	Message(const Message&) = default;
	Message(Message&&) = default;

	Message& operator=(const Message&) = default;
	Message& operator=(Message&&) = default;

	static std::unique_ptr<Message> parse(const Span<std::uint8_t>& buffer);

	std::size_t getTotalSize() const;
	const std::vector<std::uint8_t>& getContent() const;
	std::vector<std::uint8_t> serialize() const;

	template <HashAlgo Algo>
	BigInt getHash() const
	{
		return hash<Algo>(serialize());
	}

	template <typename T>
	std::enable_if_t<std::is_integral<T>::value, T> read() const
	{
		if (_data.size() - _readPos < sizeof(T))
			throw NotEnoughDataError();

		T result = *reinterpret_cast<const T*>(_data.data() + _readPos);
		_readPos += sizeof(T);
		return result;
	}

	template <typename T>
	std::enable_if_t<!std::is_integral<T>::value && std::is_default_constructible<std::decay_t<T>>::value, T> read() const
	{
		T result;
		*this >> result;
		return result;
	}

	template <typename T>
	std::enable_if_t<!std::is_integral<T>::value && !std::is_default_constructible<std::decay_t<T>>::value, T> read() const
	{
		return T{*this};
	}

	template <typename T>
	void write(std::enable_if_t<std::is_integral<T>::value, T> value)
	{
		if (_writePos + sizeof(T) > _data.size())
			_data.resize(_writePos + sizeof(T));

		std::memcpy(_data.data() + _writePos, reinterpret_cast<const std::uint8_t*>(&value), sizeof(T));
		_writePos += sizeof(T);
	}

	template <typename T>
	void write(std::enable_if_t<!std::is_integral<T>::value && std::is_default_constructible<std::decay_t<T>>::value, T&&> value)
	{
		*this << value;
	}

	template <typename T>
	std::vector<T> readSequence() const
	{
		std::size_t count = 0;

		auto firstByte = read<std::uint8_t>();
		if ((firstByte & 0x80) == 0)
		{
			count = firstByte & 0x7F;
		}
		else if ((firstByte & 0xC0) == 0x80)
		{
			auto secondByte = read<std::uint8_t>();
			count =
				(static_cast<std::size_t>(firstByte & 0x3F) << 8) |
				secondByte;
		}
		else
			throw SequenceTooLongError();

		std::vector<T> result;
		for (std::size_t i = 0; i < count; ++i)
			result.push_back(read<T>());

		return result;
	}

	template <typename T>
	void writeSequence(typename std::vector<T>::const_iterator first, typename std::vector<T>::const_iterator last)
	{
		std::size_t count = std::distance(first, last);
		if (count <= 0x7F)
		{
			write<std::uint8_t>(count);
		}
		else if (count <= 0x3FFF)
		{
			write<std::uint8_t>(0x80 | ((count >> 8) & 0x3F));
			write<std::uint8_t>(count & 0xFF);
		}
		else
			throw SequenceTooLongError();

		for (auto itr = first; itr != last; ++itr)
			write<T>(*itr);
	}

	const Message& operator>>(std::string& str) const
	{
		str.clear();

		char c;
		while ((c = read<char>()) != '\0')
			str += c;

		return *this;
	}

	template <std::size_t N>
	const Message& operator>>(std::bitset<N>& bitset) const
	{
		bitset = std::bitset<N>(read<std::string>());
		return *this;
	}

	Message& operator<<(const std::string& str)
	{
		for (auto itr = str.begin(); itr != str.end(); ++itr)
			write<char>(*itr);

		write<char>('\0');
		return *this;
	}

	template <std::size_t N>
	Message& operator<<(const std::bitset<N>& bitset)
	{
		write<std::string>(bitset.to_string());
		return *this;
	}

private:
	std::vector<std::uint8_t> _data;
	mutable std::size_t _readPos;
	std::size_t _writePos;
};
