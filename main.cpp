#include <iostream>
#include <vector>

#include <openssl/evp.h>

#include "big_int.h"
#include "service.h"

using namespace std::string_literals;

const auto socketPath = "/tmp/xmilko01.socket";

const auto dhPrime = "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D"
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
	"15728E5A8AACAA68FFFFFFFFFFFFFFFF"_bigint;

const auto dhGenerator = "2"_bigint;

void server()
{
	Server server(socketPath);
	server.start();

	auto secretKey = BigInt::random(dhPrime);
	auto publicKey = dhGenerator.raiseMod(secretKey, dhPrime);

	server.send(publicKey);
	auto otherKey = server.receive(
			[&](const Message* msg) {
				return msg->read<BigInt>();
			}
		);

	auto sharedKey = otherKey.raiseMod(secretKey, dhPrime);

	//std::cout << "My  public key: " << std::hex << publicKey << std::endl;
	//std::cout << "Oth public key: " << std::hex << otherKey << std::endl;
	//std::cout << std::endl;
	//std::cout << "Shared key: " << std::hex << sharedKey << std::endl;
}

void client()
{
	Client client(socketPath);
	client.start();

	auto secretKey = BigInt::random(dhPrime);
	auto publicKey = dhGenerator.raiseMod(secretKey, dhPrime);

	client.send(publicKey);
	auto otherKey = client.receive(
			[&](const Message* msg) {
				return msg->read<BigInt>();
			}
		);

	auto sharedKey = otherKey.raiseMod(secretKey, dhPrime);

	//std::cout << "My  public key: " << std::hex << publicKey << std::endl;
	//std::cout << "Oth public key: " << std::hex << otherKey << std::endl;
	//std::cout << std::endl;
	//std::cout << "Shared key: " << std::hex << sharedKey << std::endl;
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
