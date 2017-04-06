#pragma once

#include <string>
#include <vector>

#include <gmpxx.h>

class Message;

class BigInt
{
public:
	BigInt();
	BigInt(std::uint64_t number);
	BigInt(const std::string& number);
	BigInt(const std::vector<std::uint8_t>& bytes);
	BigInt(const BigInt&) = default;

	BigInt& operator=(const BigInt&) = default;

	static BigInt random(std::size_t numberOfBits);

	std::size_t getNumberOfBits() const;
	std::vector<std::uint8_t> getRawBytes() const;
	std::int8_t getSign() const;

	template <typename T>
	std::enable_if_t<std::is_unsigned<T>::value, T> getInteger() const
	{
		return _impl.get_ui();
	}

	template <typename T>
	std::enable_if_t<std::is_signed<T>::value, T> getInteger() const
	{
		return _impl.get_si();
	}

	BigInt raise(std::uint64_t power) const;
	BigInt raiseMod(const BigInt& power, const BigInt& mod) const;
	BigInt invertMod(const BigInt& mod) const;

	void setSign(std::int8_t sign);

	BigInt operator-() const;
	BigInt operator-(const BigInt& rhs) const;
	BigInt operator*(const BigInt& rhs) const;
	BigInt operator%(const BigInt& rhs) const;

	bool operator<(const BigInt& rhs) const;
	bool operator>(const BigInt& rhs) const;
	bool operator<=(const BigInt& rhs) const;
	bool operator>=(const BigInt& rhs) const;
	bool operator==(const BigInt& rhs) const;
	bool operator!=(const BigInt& rhs) const;

	friend std::ostream& operator<<(std::ostream& out, const BigInt& bigint);

	friend const Message& operator>>(const Message& msg, BigInt& bigint);
	friend Message& operator<<(Message& msg, const BigInt& bigint);

private:
	mpz_class _impl;
};

BigInt operator""_bigint(const char* number, std::size_t);
