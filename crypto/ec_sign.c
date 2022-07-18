#include "hblk_crypto.h"

/**
 * ec_sign - Signs given set of bytes
 * @key: Key
 * @msg: message
 * @msglen: length
 * @sig: Address for signature
 * Return: Null or sig
 */

uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg, size_t msglen, sig_t *sig)
{
	unsigned int len;

	if (!key || !msg || !msglen || !sig)
		return (NULL);

	len = sig->len;
	if (ECDSA_sign(0, msg, msglen, sig->sig, &len, (EC_KEY *)key) != 1)
		return (NULL);

	sig->len = len;
	return (sig->sig);
}
