#pragma once

#include <cstdint>
#include <vector>

#include "message.h"

class EncryptedData
{
public:
	EncryptedData() = default;
	template <typename IvT, typename DataT>
	EncryptedData(IvT&& iv, DataT&& data) : _iv(std::forward<IvT>(iv)), _data(std::forward<DataT>(data)) {}
	EncryptedData(const EncryptedData&) = default;
	EncryptedData(EncryptedData&&) = default;

	EncryptedData& operator=(const EncryptedData&) = default;
	EncryptedData& operator=(EncryptedData&&) = default;

	const std::vector<std::uint8_t>& getIV() const { return _iv; }
	const std::vector<std::uint8_t>& getData() const { return _data; }

	friend const Message& operator>>(const Message& msg, EncryptedData& encData)
	{
		auto iv = msg.readSequence<std::uint8_t>();
		auto data = msg.readSequence<std::uint8_t>();
		encData = { std::move(iv), std::move(data) };
		return msg;
	}

	friend Message& operator<<(Message& msg, const EncryptedData& encData)
	{
		msg.writeSequence<std::uint8_t>(encData._iv.begin(), encData._iv.end());
		msg.writeSequence<std::uint8_t>(encData._data.begin(), encData._data.end());
		return msg;
	}

private:
	std::vector<std::uint8_t> _iv;
	std::vector<std::uint8_t> _data;
};
