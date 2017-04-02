#pragma once

#include <cstdint>
#include <vector>

#include <openssl/sha.h>

#include "big_int.h"
#include "span.h"

enum class HashAlgo
{
	Sha256
};

template <HashAlgo Algo>
struct HashTraits {};

template <>
struct HashTraits<HashAlgo::Sha256>
{
	using FnType = decltype(&SHA256);

	constexpr static const FnType Fn = &SHA256;
	constexpr static const std::size_t DigestSize = SHA256_DIGEST_LENGTH;
};

template <HashAlgo Algo>
BigInt hash(const Span<std::uint8_t>& data)
{
	std::vector<std::uint8_t> result(HashTraits<Algo>::DigestSize);
	(*HashTraits<Algo>::Fn)(data.getData(), data.getSize(), result.data());
	return result;
}

template <HashAlgo Algo>
BigInt hash(const std::vector<std::uint8_t>& data)
{
	return hash<Algo>({data.data(), data.size()});
}
