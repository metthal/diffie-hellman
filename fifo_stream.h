#pragma once

#include <fstream>
#include <type_traits>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "utilities.h"

struct FifoInput {};
struct FifoOutput {};
struct FifoIO {};

namespace detail {

template <typename Tag> struct FifoStreamTraits {};

template <> struct FifoStreamTraits<FifoInput>
{
	using StreamType = std::ifstream;
};

template <> struct FifoStreamTraits<FifoOutput>
{
	using StreamType = std::ofstream;
};

template <> struct FifoStreamTraits<FifoIO>
{
	using StreamType = std::fstream;
};

}

template <typename Tag, typename = std::enable_if_t<IsOneOf<Tag, FifoInput, FifoOutput, FifoIO>::value>>
class FifoStream
{
public:
	using StreamType = typename detail::FifoStreamTraits<Tag>::StreamType;

	FifoStream(const std::string& path) : _path(path), _fd(-1), _stream()
	{
		if ((_fd = mkfifo(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
		{
			if (errno != EEXIST)
				throw std::exception();
		}

		_stream.open(path);
		if (!_stream.is_open())
			throw std::exception();
	}

	~FifoStream()
	{
		if (_fd != -1)
		{
			close(_fd);
			std::remove(_path.c_str());
		}
	}

	StreamType& operator()() { return _stream; }

private:
	std::string _path;
	int _fd;
	StreamType _stream;
};
