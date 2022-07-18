#include "hblk_crypto.h"

/**
 * ec_create - Creates new EC key pair
 * Return: EC_KEY
 *
 */

EC_KEY *ec_create(void)
{
	EC_KEY *key;

	key = EC_KEY_new_by_curve_name(EC_CURVE);
	if (!key)
		return (NULL);

	if (!EC_KEY_generate_key(key))
	{
		EC_KEY_free(key);
		return (NULL);
	}
	return (key);
}


