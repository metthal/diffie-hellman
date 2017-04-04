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

BigInt::BigInt(const std::string& number) : _impl(number.c_str())
{
}

BigInt::BigInt(const std::vector<std::uint8_t>& bytes) : _impl()
{
	mpz_import(_impl.get_mpz_t(), bytes.size(), 1, 1, 0, 0, bytes.data());
}

BigInt BigInt::random(std::size_t numberOfBits)
{
	auto number = BN_new();

	BN_rand(number, numberOfBits, 1, 0);
	std::vector<std::uint8_t> bytes(BN_num_bytes(number));
	BN_bn2bin(number, bytes.data());

	BN_clear_free(number);
	return bytes;
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

std::int8_t BigInt::getSign() const
{
	return sgn(_impl);
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

BigInt BigInt::invertMod(const BigInt& mod) const
{
	BigInt result;
	mpz_invert(result._impl.get_mpz_t(), _impl.get_mpz_t(), mod._impl.get_mpz_t());
	return result;
}

void BigInt::setSign(std::int8_t sign)
{
	if (getSign() == sign)
		return;

	_impl = -_impl;
}

BigInt BigInt::operator-() const
{
	BigInt result = *this;
	result.setSign(!result.getSign());
	return result;
}

BigInt BigInt::operator-(const BigInt& rhs) const
{
	BigInt result;
	result._impl = _impl - rhs._impl;
	return result;
}

BigInt BigInt::operator*(const BigInt& rhs) const
{
	BigInt result;
	result._impl = _impl * rhs._impl;
	return result;
}

bool BigInt::operator<(const BigInt& rhs) const
{
	return _impl < rhs._impl;
}

bool BigInt::operator>(const BigInt& rhs) const
{
	return _impl > rhs._impl;
}

bool BigInt::operator<=(const BigInt& rhs) const
{
	return _impl <= rhs._impl;
}

bool BigInt::operator>=(const BigInt& rhs) const
{
	return _impl >= rhs._impl;
}

bool BigInt::operator==(const BigInt& rhs) const
{
	return _impl == rhs._impl;
}

bool BigInt::operator!=(const BigInt& rhs) const
{
	return !(*this == rhs);
}

const Message& operator>>(const Message& msg, BigInt& bigint)
{
	auto sign = msg.read<std::int8_t>();
	auto bytes = msg.readSequence<std::uint8_t>();
	bigint = bytes;
	bigint.setSign(sign);
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
	msg.write<std::int8_t>(bigint.getSign());
	msg.writeSequence<std::uint8_t>(bytes.begin(), bytes.end());
	return msg;
}

BigInt operator""_bigint(const char* number, std::size_t)
{
	return BigInt{number};
}
