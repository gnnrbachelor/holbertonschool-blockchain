#include "hblk_crypto.h"

/**
 * sha256 - Computes has of sequence of bytes
 * @s: sequence of bytes
 * @len: length of bytes to hash
 * @digest: Buffer
 * Return: Pointer to digest
 *
 */

uint8_t *sha256(int8_t const *s, size_t len, uint8_t digest[SHA256_DIGEST_LENGTH])
{
	if (!s || !digest)
		return (NULL);
	return (SHA256((const unsigned char *)s, len, digest));
}
