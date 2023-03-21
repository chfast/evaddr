#include <ethash/keccak.hpp>
#include <iomanip>
#include <iostream>
#include <secp256k1.h>

// 0000000000000000000000000000000000000000000000000000000001ef0dff 0xe7804E2A1BE4259b886cbbee0fc29Bb25Fe5B8b1
// 0000000000000000000000000000000000000000000000000000000100e79ba3 0xe7804eCe3629Ac1cC345FDCD9a37e241732e5F61
// 00000000000000000000000000000000000000000000000000000000804aacc8 0xe7804E3935dF58A998DA577525e6e18B0ebF3A5d
// 000000000000000000000000000000000000000000000000000000008053912b 0xE7804e969f01911E17dc8B942692cd9536c5e0B5
// 0000000000000000000000000000000000000000000000000000000010fd5eba 0xe7804E050e7Fc819976FeeEBf1f65FACf9940fCE
// 000000000000000000000000000000000000000000000000000000008125918c 0xE7804eE5a89Fe0A4681F855F5629A681304c1A14

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
		if (h.bytes[12] == 0xEF && h.bytes[13] == 0x00 && h.bytes[14] == 0x01)
		{
			std::cout << std::hex << "seckey: " << i << "\n";
			for (int j = 12; j < 32; ++j)
				std::cout << std::setfill('0') << std::setw(2) << int(h.bytes[j]);
			std::cout << "\n";
		}
	}

	return 0;
}
