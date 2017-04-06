#pragma once

#include <memory>
#include <vector>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "encrypted_data.h"

enum Cipher
{
	Aes256Cbc
};

template <Cipher C>
struct CipherTraits {};

template <>
struct CipherTraits<Cipher::Aes256Cbc>
{
	using InitFnType = decltype(&EVP_aes_256_cbc);

	constexpr static const InitFnType InitFn = &EVP_aes_256_cbc;
	constexpr static const std::size_t BlockSize = AES_BLOCK_SIZE;
	constexpr static const std::size_t IVSize = AES_BLOCK_SIZE;
	constexpr static const char* Name = "AES-256-CBC";
};

class CipherEngineBase
{
public:
	CipherEngineBase(const BigInt& key) : _impl(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free), _key(key) {}

	virtual EncryptedData encrypt(const Message& msg) const = 0;
	virtual Message decrypt(const EncryptedData& ciphertext) const = 0;

protected:
	using HandleType = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

	HandleType _impl;
	BigInt _key;
};

template <Cipher C>
class CipherEngine : public CipherEngineBase
{
public:
	CipherEngine(const BigInt& key) : CipherEngineBase(key)
	{
		EVP_add_cipher(CipherTraits<C>::InitFn());
	}

	virtual EncryptedData encrypt(const Message& msg) const override
	{
		const auto& plaintext = msg.getContent();

		std::vector<std::uint8_t> iv(CipherTraits<C>::IVSize);
		RAND_bytes(iv.data(), iv.size());

		EVP_EncryptInit_ex(_impl.get(), CipherTraits<C>::InitFn(), nullptr, _key.getRawBytes().data(), iv.data());

		int bytesWritten = 0;
		std::vector<std::uint8_t> ciphertext(plaintext.size() + CipherTraits<C>::BlockSize);
		EVP_EncryptUpdate(_impl.get(), ciphertext.data(), &bytesWritten, plaintext.data(), plaintext.size());

		int finalBytesWritten = 0;
		EVP_EncryptFinal_ex(_impl.get(), ciphertext.data() + bytesWritten, &finalBytesWritten);
		ciphertext.resize(bytesWritten + finalBytesWritten);

		return { std::move(iv), std::move(ciphertext) };
	}

	virtual Message decrypt(const EncryptedData& ciphertext) const override
	{
		EVP_DecryptInit_ex(_impl.get(), CipherTraits<C>::InitFn(), nullptr, _key.getRawBytes().data(), ciphertext.getIV().data());

		int bytesWritten = 0;
		std::vector<std::uint8_t> plaintext(ciphertext.getData().size());
		EVP_DecryptUpdate(_impl.get(), plaintext.data(), &bytesWritten, ciphertext.getData().data(), ciphertext.getData().size());

		int finalBytesWritten = 0;
		EVP_DecryptFinal_ex(_impl.get(), plaintext.data() + bytesWritten, &finalBytesWritten);
		plaintext.resize(bytesWritten + finalBytesWritten);

		return plaintext;
	}
};
