#include <iostream>
#include <vector>

#include "big_int.h"
#include "cipher_engine.h"
#include "hash.h"
#include "service.h"

const auto socketPath = "/tmp/kry-xmilko01.socket";

// Diffie_Hellman parameters
const auto dhGenerator = "2"_bigint;
const auto dhModulus = "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
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

// Feige-Fiat-Shamir parameters
const auto authenticationTries = 4;
const auto ffsN = "6854094740328716964537162194987044147141068353435567001423495886123986431524484180445077931935555842918624004333312819870"
	"768234350338831770704569330358466595153891946219009802123179173846336429131525643935623013369566827022032382397164259862427478592037668"
	"806680871173899594707261102765034694450679268176745975368118568508461153092679300169555029731508192995713218354934548201765849829866564"
	"705211040032434877100776622388338510367704268096270459411126422808037880654833042742865847679830939071485129307797779927643477548400238"
	"9275941552005040119499664225566691847461439020540844282757762659001103626502226286465445073"_bigint;
const auto ffsS = std::vector<BigInt>{
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
};

bool server()
{
	Server server(socketPath);

	try
	{
		std::cout << "=== Staring server and waiting for client..." << std::endl;
		server.start();

		std::cout << "=== Starting Diffie-Hellman key exchange..." << std::endl;
		server.createSecuredChannel<Cipher::Aes256Cbc, HashAlgo::Sha256>(dhGenerator, dhModulus);
		std::cout << "=== Diffie-Hellman key exchange completed. All communication is now encrypted with " << CipherTraits<Cipher::Aes256Cbc>::Name << '.' << std::endl;

		for (auto i = 0; i < authenticationTries; ++i)
		{
			std::cout << "=== Authenticating client... ";
			if (!server.verifyAuthentication(ffsN, ffsS.size()))
			{
				std::cout << "FAIL" << std::endl;
				return false;
			}
			std::cout << "OK" << std::endl;
		}

		// Message exchange
		while (true)
		{
			server.receive(
					[&](const Message* msg) {
						auto str = msg->read<std::string>();
						auto msgHash = msg->getHash<HashAlgo::Sha256>();
						std::cout << "=== Received: " << str << " (" << hashToString<HashAlgo::Sha256>(msgHash) << ')' << std::endl;
						server.send(msgHash);
					}
				);
		}
	}
	catch(const ConnectionClosedError&)
	{
	}
	catch(const ConnectionFailureError&)
	{
		std::cerr << "=== Client disconnected unexpectedly.\n";
		return false;
	}

	return true;
}

bool client()
{
	Client client(socketPath);

	try
	{
		client.start();

		std::cout << "=== Starting Diffie-Hellman key exchange..." << std::endl;
		client.createSecuredChannel<Cipher::Aes256Cbc, HashAlgo::Sha256>(dhGenerator, dhModulus);
		std::cout << "=== Diffie-Hellman key exchange completed. All communication is now encrypted with " << CipherTraits<Cipher::Aes256Cbc>::Name << '.' << std::endl;

		for (auto i = 0; i < authenticationTries; ++i)
		{
			std::cout << "=== Sending authentication info to server..." << std::endl;
			client.authenticate(ffsN, ffsS);
		}

		std::cout << "=== Awaiting input..." << std::endl;
		bool keepAlive = true;
		std::string line;
		while (keepAlive && std::getline(std::cin, line))
		{
			auto sentMsg = client.send(line);
			auto sentMsgHash = sentMsg.getHash<HashAlgo::Sha256>();
			std::cout << "=== Sent: " << line << " (" << hashToString<HashAlgo::Sha256>(sentMsgHash) << ')' << std::endl;
			keepAlive = client.receive(
					[&](const Message* msg) {
						auto recvdHash = msg->read<BigInt>();
						bool hashesEqual = sentMsgHash == recvdHash;
						std::cout << "=== Comparing hashes... " << (hashesEqual ? "OK" : "MISMATCH") << std::endl;
						return hashesEqual;
					}
				);
		}
	}
	catch(const ConnectionClosedError&)
	{
	}
	catch(const ConnectionFailureError&)
	{
		std::cerr << "=== Server disconnected unexpectedly.\n";
		return false;
	}
	catch(const UnableToConnectError&)
	{
		std::cerr << "=== Unable to connect to the server.\n";
		return false;
	}

	return true;
}

int main(int argc, char* argv[])
{
	std::vector<std::string> args(argv + 1, argv + argc);
	if (args.size() != 1)
		return 1;

	bool ok = true;
	if (args[0] == "-s")
		ok = server();
	else if (args[0] == "-c")
		ok = client();
	else
		return 1;

	EVP_cleanup();
	return ok ? 0 : 1;
}
