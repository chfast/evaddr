#include <ethash/keccak.hpp>
#include <iomanip>
#include <iostream>
#include <secp256k1.h>

int main(int argc, const char* argv[])
{
	const auto ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

	secp256k1_pubkey pubkey;
	uint8_t seckey[32]{};
	uint8_t out[65]{};
	auto out_len = sizeof(out);
	ethash_hash256 h{};

	const auto start_i = argc >= 2 ? std::strtoull(argv[1], nullptr, 0) : 1;

	for (uint64_t i = start_i; true; ++i)
	{
		const auto bi = __builtin_bswap64(i);
		__builtin_memcpy(&seckey[sizeof(seckey) - sizeof(bi)], &bi, sizeof(bi));
		if (secp256k1_ec_pubkey_create(ctx, &pubkey, seckey) == 0)
			return 1;
		secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
		h = ethash_keccak256(out + 1, 64);

		// e7804e
		if (h.bytes[12] == 0xe7 && h.bytes[13] == 0x80 && h.bytes[14] == 0x4e)
		{
			std::cout << std::hex << "seckey: " << i << "\n";
			for (int j = 12; j < 32; ++j)
				std::cout << std::setfill('0') << std::setw(2) << int(h.bytes[j]);
			std::cout << "\n";
		}
	}

	return 0;
}
