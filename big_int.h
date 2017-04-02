#pragma once

#include <string>

#include <gmpxx.h>

class Message;

class BigInt
{
public:
	BigInt();
	BigInt(std::uint64_t number);
	BigInt(const char* number);
	BigInt(const std::string& number);
	BigInt(const BigInt&) = default;

	BigInt& operator=(const BigInt&) = default;

	static BigInt random(const BigInt& max);

	std::size_t getNumberOfBits() const;

	BigInt raise(std::uint64_t power) const;
	BigInt raiseMod(const BigInt& power, const BigInt& mod) const;

	operator std::uint64_t() const;

	friend std::ostream& operator<<(std::ostream& out, const BigInt& bigint);

	friend const Message& operator>>(const Message& msg, BigInt& bigint);
	friend Message& operator<<(Message& msg, const BigInt& bigint);

private:
	mpz_class _impl;
};

BigInt operator""_bigint(const char* number, std::size_t);
