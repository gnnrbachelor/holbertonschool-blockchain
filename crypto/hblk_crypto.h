#ifndef HBLK_CRYPTO_H
#define HBLK_CRYPTO_H


#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>


#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>

#define EC_CURVE   NID_secp256k1
#define EC_PUB_LEN 65
#define PRIV_FILE "key.pem"
#define PUB_FILE "key_pub.pem"
#define PRIVATE "/key.pem"
#define PUBLIC "/key_pub.pem"
#define SIG_MAX_LEN    72


/**
 * struct sig_s - Sig struct
 * @sig: Sig
 * @len: length
 *
 */

typedef struct sig_s
{
	uint8_t     sig[SIG_MAX_LEN];
	uint8_t     len;
} sig_t;


uint8_t *sha256(int8_t const *s, size_t len,
uint8_t digest[SHA256_DIGEST_LENGTH]);
EC_KEY *ec_create(void);
uint8_t *ec_to_pub(EC_KEY const *key, uint8_t pub[EC_PUB_LEN]);
EC_KEY *ec_from_pub(uint8_t const pub[EC_PUB_LEN]);
int ec_save(EC_KEY *key, char const *folder);
EC_KEY *ec_load(char const *folder);
uint8_t *ec_sign(EC_KEY const *key, uint8_t const *msg,
	 size_t msglen, sig_t *sig);
int ec_verify(EC_KEY const *key, uint8_t const *msg,
	 size_t msglen, sig_t const *sig);

#endif
