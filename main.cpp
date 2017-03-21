#include <iostream>
#include <vector>

#include "fifo_stream.h"

const std::string PipeName = "pipe";

void server()
{
	FifoStream<FifoInput> fifo(PipeName);
	std::string str;
	fifo() >> str;
	std::cout << str << std::endl;
}

void client()
{
	FifoStream<FifoOutput> fifo(PipeName);
	fifo() << "Hello World!";
}

int main(int argc, char* argv[])
{
	std::vector<std::string> args(argv + 1, argv + argc);
	if (args.size() != 1)
		return 1;

	if (args[0] == "-s")
		server();
	else if (args[0] == "-c")
		client();
	else
		return 1;

	return 0;
}
