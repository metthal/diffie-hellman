#include "utils.h"

boost::dynamic_bitset<std::uint64_t> randomBits(std::size_t numberOfBits)
{
	std::uint64_t bits;
	RAND_bytes(reinterpret_cast<std::uint8_t*>(&bits), sizeof(bits));
	return boost::dynamic_bitset<std::uint64_t>(numberOfBits, bits);
}
