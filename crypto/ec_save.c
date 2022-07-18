#include "hblk_crypto.h"


/**
 * ec_save - Saves EC key pair
 * @key: Key
 * @folder: Folder
 * Return: 1 or 0
 *
 */

int ec_save(EC_KEY *key, char const *folder)
{
	FILE *priv_file, *pub_file;
	char *priv_path = NULL, *pub_path = NULL;


	if (!key || !folder)
		return (0);

	mkdir(folder, S_IROTH | S_IXOTH | S_IRWXU | S_IRWXG);

	priv_path = calloc(strlen(folder) + strlen(PRIV_FILE) + 1, 1);
	if (!priv_path)
		return (0);

	pub_path = calloc(strlen(folder) + strlen(PUB_FILE) + 1, 1);
	if (!pub_path)
	{
		free(priv_path);
		return (0);
	}

	strcpy(priv_path, folder);
	strcat(priv_path, PRIVATE);
	priv_file = fopen(priv_path, "w+");
	if (!PEM_write_ECPrivateKey(priv_file, key, NULL, NULL, 0, NULL, NULL))
	{
		fclose(priv_file);
		return (0);
	}
	fclose(priv_file);

	strcpy(pub_path, folder);
	strcat(pub_path, PUBLIC);
	pub_file = fopen(pub_path, "w+");
	if (!PEM_write_EC_PUBKEY(pub_file, key))
	{
		fclose(pub_file);
		return (0);
	}
	fclose(pub_file);
	return (1);
}

