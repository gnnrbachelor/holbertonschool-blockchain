#include "hblk_crypto.h"

/**
 * ec_load - Loads EC pair from disk
 * @folder : Folder
 * Return: Pointer to key pair or NULL
 *
 */

EC_KEY *ec_load(char const *folder)
{
	FILE *priv_file = NULL, *pub_file = NULL;
	char *priv_path = NULL, *pub_path = NULL;
	EC_KEY *key = NULL;

	if (!folder)
		return (NULL);

	priv_path = calloc(strlen(folder) + strlen(PRIVATE) + 1, 1);
	if (!priv_path)
		return (NULL);
	pub_path = calloc(strlen(folder) + strlen(PUBLIC) + 1, 1);
	if (!pub_path)
		return (NULL);

	strcpy(priv_path, folder);
	strcat(priv_path, PRIVATE);
	priv_file = fopen(priv_path, "r");
	strcpy(pub_path, folder);
	strcat(pub_path, PUBLIC);
	pub_file = fopen(pub_path, "r");
	free(priv_path);
	free(pub_path);
	if (!priv_file || !pub_file)
		return (NULL);

	if (!PEM_read_EC_PUBKEY(pub_file, &key, NULL, NULL))
	{
		fclose(pub_file);
		return (NULL);
	}
	fclose(pub_file);

	if (!PEM_read_EC_PUBKEY(priv_file, &key, NULL, NULL))
	{
		fclose(priv_file);
		return (NULL);
	}
	fclose(priv_file);
	return (key);
}
