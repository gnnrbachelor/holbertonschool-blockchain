#include "hblk_crypto.h"

/**
 * ec_verify - Verifies sig
 * @key: Key
 * @msg: Message
 * @msglen: Length
 * @sig: Signature
 * Return: Sig or NULL
 */

int ec_verify(EC_KEY const *key, uint8_t const *msg,
	 size_t msglen, sig_t const *sig)
{
	int res = 0;

	if (!key || !msg || !sig)
		return (res);

	res = ECDSA_verify(0, msg, msglen, sig->sig, sig->len, (EC_KEY *)key);
	return (res == 1);
}

