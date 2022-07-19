#include "hblk_crypto.h"

static int priv_save(EC_KEY *key, char const *folder)
{

	FILE *priv_file = NULL;
	char *priv_path = NULL;

	priv_path = calloc(strlen(folder) + strlen(PRIVATE) + 1, 1);
	if (!priv_path)
		return (0);

	strcpy(priv_path, folder);
	strcat(priv_path, PRIVATE);
	priv_file = fopen(priv_path, "w+");
	if (!PEM_write_ECPrivateKey(priv_file, key, NULL, NULL, 0, NULL, NULL))
	{
		fclose(priv_file);
		free(priv_path);
		return (0);
	}
	fclose(priv_file);
	free(priv_path);
	return (1);

}

static int pub_save(EC_KEY *key, char const *folder)
{

	FILE *pub_file = NULL;
	char *pub_path = NULL;

	pub_path = calloc(strlen(folder) + strlen(PUBLIC) + 1, 1);
	if (!pub_path)
		return (0);

	strcpy(pub_path, folder);
	strcat(pub_path, PUBLIC);
	pub_file = fopen(pub_path, "w+");
	if (!PEM_write_EC_PUBKEY(pub_file, key))
	{
		fclose(pub_file);
		free(pub_path);
		return (0);
	}
	fclose(pub_file);
	free(pub_path);

	return (1);

}


/**
 * ec_save - Saves EC key pair
 * @key: Key
 * @folder: Folder
 * Return: 1 or 0
 *
 */

int ec_save(EC_KEY *key, char const *folder)
{

	if (!key || !folder)
		return (0);

	mkdir(folder, 0777);

	if (!pub_save(key, folder))
		return (0);

	if (!priv_save(key, folder))
		return (0);

	return (1);
}

