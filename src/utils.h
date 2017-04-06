#pragma once

#include <bitset>

#include <openssl/rand.h>

template <std::size_t N>
std::bitset<N> randomBits()
{
	static_assert(0 < N && N <= sizeof(std::uint64_t) * 8, "Unsupported size of random bits.");

	std::uint64_t bits;
	RAND_bytes(reinterpret_cast<std::uint8_t*>(&bits), sizeof(bits));
	return std::bitset<N>(bits);
}
