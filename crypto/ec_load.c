#include "hblk_crypto.h"

/**
 * pub_load - Loads public key
 * @folder: Folder
 * @key: Key
 * Return: EC_KEY stuct or NULL
 */

static EC_KEY *pub_load(char const *folder, EC_KEY *key)
{
	FILE *pub_file = NULL;
	char *pub_path = NULL;

	pub_path = calloc(strlen(folder) + strlen(PUBLIC) + 1, 1);
	if (!pub_path)
		return (NULL);

	strcpy(pub_path, folder);
	strcat(pub_path, PUBLIC);
	pub_file = fopen(pub_path, "r");
	free(pub_path);
	if (!pub_file)
		return (NULL);

	if (!PEM_read_EC_PUBKEY(pub_file, &key, NULL, NULL))
	{
		fclose(pub_file);
		return (NULL);
	}
	fclose(pub_file);
	return (key);
}

/**
 * priv_load - Loads private key
 * @folder: Folder
 * @key: Key
 * Return: EC_KEY stuct or NULL
 */


static EC_KEY *priv_load(char const *folder, EC_KEY *key)
{
	FILE *priv_file = NULL;
	char *priv_path = NULL;

	priv_path = calloc(strlen(folder) + strlen(PRIVATE) + 1, 1);
	if (!priv_path)
		return (NULL);

	strcpy(priv_path, folder);
	strcat(priv_path, PRIVATE);
	priv_file = fopen(priv_path, "r");
	if (!priv_file)
		return (NULL);

	free(priv_path);

	if (!PEM_read_ECPrivateKey(priv_file, &key, NULL, NULL))
	{
		fclose(priv_file);
		return (NULL);
	}
	fclose(priv_file);
	return (key);

}



/**
 * ec_load - Loads EC pair from disk
 * @folder : Folder
 * Return: Pointer to key pair or NULL
 *
 */

EC_KEY *ec_load(char const *folder)
{
	EC_KEY *key = NULL;

	if (!folder)
		return (NULL);

	priv_load(folder, key);
	pub_load(folder, key);

	return (key);
}
