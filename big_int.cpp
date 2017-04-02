#include <iostream>

#include <gmp.h>

#include <openssl/bn.h>

#include "big_int.h"
#include "message.h"

BigInt::BigInt() : _impl()
{
}

BigInt::BigInt(std::uint64_t number) : _impl(number)
{
}

BigInt::BigInt(const char* number) : _impl(number)
{
}

BigInt::BigInt(const std::string& number) : BigInt(number.c_str())
{
}

BigInt::BigInt(const std::vector<std::uint8_t>& bytes) : _impl()
{
	mpz_import(_impl.get_mpz_t(), bytes.size(), 1, 1, 0, 0, bytes.data());
}

BigInt BigInt::random(const BigInt& max)
{
	auto number = BN_new();

	BN_rand(number, max.getNumberOfBits() - 1, 1, 0);
	std::vector<std::uint8_t> bytes(BN_num_bytes(number));
	BN_bn2bin(number, bytes.data());
	BN_clear_free(number);

	return bytes;
}

BigInt::operator std::uint64_t() const
{
	return _impl.get_ui();
}

std::size_t BigInt::getNumberOfBits() const
{
	return mpz_sizeinbase(_impl.get_mpz_t(), 2);
}

std::vector<std::uint8_t> BigInt::getRawBytes() const
{
	size_t size = getNumberOfBits() / 8 + 1;

	std::vector<std::uint8_t> bytes(size);
	mpz_export(bytes.data(), &size, 1, 1, 0, 0, _impl.get_mpz_t());
	bytes.resize(size);

	return bytes;
}

BigInt BigInt::raise(std::uint64_t power) const
{
	BigInt result;
	mpz_pow_ui(result._impl.get_mpz_t(), _impl.get_mpz_t(), power);
	return result;
}

BigInt BigInt::raiseMod(const BigInt& power, const BigInt& mod) const
{
	BigInt result;
	mpz_powm(result._impl.get_mpz_t(), _impl.get_mpz_t(), power._impl.get_mpz_t(), mod._impl.get_mpz_t());
	return result;
}

const Message& operator>>(const Message& msg, BigInt& bigint)
{
	auto bytes = msg.readSequence<std::uint8_t>();
	bigint = bytes;
	return msg;
}

std::ostream& operator<<(std::ostream& out, const BigInt& bigint)
{
	out << bigint._impl;
	return out;
}

Message& operator<<(Message& msg, const BigInt& bigint)
{
	auto bytes = bigint.getRawBytes();
	msg.writeSequence<std::uint8_t>(bytes.begin(), bytes.end());
	return msg;
}

BigInt operator""_bigint(const char* number, std::size_t)
{
	return BigInt{number};
}
