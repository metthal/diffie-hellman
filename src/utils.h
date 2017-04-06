#pragma once

#include <bitset>

#include <boost/dynamic_bitset.hpp>

#include <openssl/rand.h>

boost::dynamic_bitset<std::uint64_t> randomBits(std::size_t numberOfBits);
