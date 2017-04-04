#include <bitset>
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

const auto ffsN = "6854094740328716964537162194987044147141068353435567001423495886123986431524484180445077931935555842918624004333312819870"
	"768234350338831770704569330358466595153891946219009802123179173846336429131525643935623013369566827022032382397164259862427478592037668"
	"806680871173899594707261102765034694450679268176745975368118568508461153092679300169555029731508192995713218354934548201765849829866564"
	"705211040032434877100776622388338510367704268096270459411126422808037880654833042742865847679830939071485129307797779927643477548400238"
	"9275941552005040119499664225566691847461439020540844282757762659001103626502226286465445073"_bigint;
const auto ffsS = std::array<BigInt, 5>{{
	"134627368046300552427213971528104503574802276462752360572449387008678412666545109350352053965887049525763213237888074548437224344385138"
		"30037582842914734413992703663821923324154958251979486288443708792361188361074274969530207122868456238651087396104167358939516245927"
		"9671886897123837452469539076695340931353283"_bigint,
	"305720623684541830382357813174126029572888631512807696562043329322051733106703141875635517872428472166185802005522830245254865302672537"
		"66100482693842740291209585559262106971141610901161409536404597278949464549570059628407105904318512095356799626487855944853455580447"
		"753546642226583693575593097486168856693183"_bigint,
	"119925541934206168022269974280027645238316170164087398691457253785998088673324437188441316732899429768497870197942410390497397537518637"
		"98558481766268133289942476026866293856884861401917243107268289710931977422012070587349157831256048318188104862768896006005771383972"
		"2276384686732650457446521916563823532945558"_bigint,
	"163824803353976558309704168845282494449802842384031872339220008472998725791673617970083314497443372239716700354951383227631141118458848"
		"05102790005957014623966775102121458245607889979406601053796154867987352404712140962107572703120398778495079884459467648135222820392"
		"7250750932942883988689332663391207969147633"_bigint,
	"179666982146692031553424715309143768519745212741152008073209265291978766479247697385798876093698815035272972016125798688468091605771393"
		"64987829414721871273044413071629544628638710464916371816036580416416817070896269491500551737921441363159992115746550168590679593655"
		"3844375731335252153836344762325956046790606"_bigint
}};

void server()
{
	Server server(socketPath);
	server.start();

	/// Diffie-Hellman key exchange
	// Calculate secret exponent E and public key G^E mod P
	auto secretExp = BigInt::random(dhPrime.getNumberOfBits() - 1);
	auto publicKey = dhGenerator.raiseMod(secretExp, dhPrime);

	// Send public key and receive public key from the other side
	server.send(publicKey);
	auto clientPublicKey = server.receive(
			[&](const Message* msg) {
				return msg->read<BigInt>();
			}
		);

	// Calculate shared secret and derive AES key from it using SHA256
	auto sharedSecret = clientPublicKey.raiseMod(secretExp, dhPrime);
	auto aesKey = hash<HashAlgo::Sha256>(sharedSecret.getRawBytes());

	// From now on, all communication is encrypted
	server.setCipher<Cipher::Aes256Cbc>(aesKey);

	/// Feige-Fiat-Shamir authentication
	// Receive public key vector from the client
	std::vector<BigInt> ffsV(ffsS.size());
	for (auto i = 0; i < 5; ++i)
	{
		server.receive(
				[&](const Message* msg) {
					ffsV.push_back(msg->read<BigInt>());
				}
			);
	}

	// Message exchange
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

	/// Diffie-Hellman key exchange
	// Calculate secret exponent E and public key G^E mod P
	auto secretExp = BigInt::random(dhPrime.getNumberOfBits() - 1);
	auto publicKey = dhGenerator.raiseMod(secretExp, dhPrime);

	client.send(publicKey);
	auto serverPublicKey = client.receive(
			[&](const Message* msg) {
				return msg->read<BigInt>();
			}
		);

	// Calculate shared secret and derive AES key from it using SHA256
	auto sharedSecret = serverPublicKey.raiseMod(secretExp, dhPrime);
	auto aesKey = hash<HashAlgo::Sha256>(sharedSecret.getRawBytes());

	// From now on, all communication is encrypted
	client.setCipher<Cipher::Aes256Cbc>(aesKey);

	/// Feige-Fiat-Shamir authentication
	// Calculate public key vector and send it to the server
	auto signs = randomBits<5>();
	std::size_t bitCounter = 0;
	std::for_each(ffsS.begin(), ffsS.end(),
			[&](const auto& s) {
				auto sSq = s.raise(2);
				sSq.setSign(signs[bitCounter++] ? -1 : 1);
				client.send(sSq.invertMod(ffsN));
			});

	// Message exchange
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
