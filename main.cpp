#include <iomanip>
#include <iostream>
#include <vector>

#include <openssl/evp.h>

#include "big_int.h"
#include "cipher_engine.h"
#include "hash.h"
#include "service.h"
#include "utils.h"

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
	auto clientPublicKey = server.receive(
			[&](const Message* msg) {
				return msg->read<BigInt>();
			}
		);

	auto sharedSecret = clientPublicKey.raiseMod(secretKey, dhPrime);
	auto aesKey = hash<HashAlgo::Sha256>(sharedSecret.getRawBytes());

	server.setCipher<Cipher::Aes256Cbc>(aesKey);

	for (auto i = 0; i < 2; ++i)
	{
		server.receive(
				[&](const Message* msg) {
					auto str = msg->read<std::string>();
					auto msgHash = msg->getHash<HashAlgo::Sha256>();
					std::cout << "Message received: " << str << " (" << msgHash << ')' << std::endl;

					server.send(msgHash);
				}
			);
	}
}

void client()
{
	Client client(socketPath);
	client.start();

	auto secretKey = BigInt::random(dhPrime);
	auto publicKey = dhGenerator.raiseMod(secretKey, dhPrime);

	client.send(publicKey);
	auto serverPublicKey = client.receive(
			[&](const Message* msg) {
				return msg->read<BigInt>();
			}
		);

	auto sharedSecret = serverPublicKey.raiseMod(secretKey, dhPrime);
	auto aesKey = hash<HashAlgo::Sha256>(sharedSecret.getRawBytes());

	client.setCipher<Cipher::Aes256Cbc>(aesKey);

	const auto valuesToSend = std::vector<std::string>{
			"Hello World",
			"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
				"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
				"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur."
				"Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
		};
	for (const auto& value : valuesToSend)
	{
		auto sentMsg = client.send(value);
		client.receive(
				[&](const Message* msg) {
					auto sentMsgHash = sentMsg.getHash<HashAlgo::Sha256>();
					auto recvdHash = msg->read<BigInt>();
					bool hashesEqual = sentMsgHash == recvdHash;
					std::cout << "Received hash: " << recvdHash << " - " << (hashesEqual ? "OK" : "MISMATCH") << std::endl;
				}
			);
	}
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

	EVP_cleanup();
	return 0;
}
