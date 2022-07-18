#include <stdlib.h>
#include <stdio.h>

#include "hblk_crypto.h"

uint8_t *ec_to_pub(EC_KEY const *key, uint8_t pub[EC_PUB_LEN]);
EC_KEY *ec_load(char const *folder);

/**
 * _print_hex_buffer - Prints a buffer in its hexadecimal form
 *
 * @buf: Pointer to the buffer to be printed
 * @len: Number of bytes from @buf to be printed
 */
static void _print_hex_buffer(uint8_t const *buf, size_t len)
{
	size_t i;

	for (i = 0; buf && i < len; i++)
		printf("%02x", buf[i]);
}

/**
 * main - Entry point
 *
 * @ac: Arguments count
 * @av: Arguments vector
 *
 * Return: EXIT_SUCCESS or EXIT_FAILURE
 */
int main(int ac, char **av)
{
	EC_KEY *key;
	uint8_t pub[EC_PUB_LEN];

	if (ac < 2)
	{
		fprintf(stderr, "Usage: %s <path>\n", av[0]);
		return (EXIT_FAILURE);
	}

	key = ec_load("_keys/alex");
	ec_to_pub(key, pub);

	printf("Public key: ");
	_print_hex_buffer(pub, EC_PUB_LEN);
	printf("\n");

	/* Test `ec_save()` */
	ec_save(key, av[1]);

	/* Cleanup */
	EC_KEY_free(key);

	return (EXIT_SUCCESS);
}
