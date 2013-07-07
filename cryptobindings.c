#include <stdio.h>
#include <openssl/hmac.h>

typedef enum { SHA1, SHA128, SHA224, SHA256, SHA384, SHA512, MD5 } hmac_engine_t;

u_int32_t wrap_HMAC(hmac_engine_t method, char *key, size_t key_size, char *data, size_t size, char *target) {

	const EVP_MD *hash_engine;
	u_int32_t digest_size;

	switch(method) {
		case SHA1:   hash_engine = EVP_sha1();   digest_size = 20; break;
		case SHA224: hash_engine = EVP_sha224(); digest_size = 28; break;
		case SHA256: hash_engine = EVP_sha256(); digest_size = 32; break;
		case SHA384: hash_engine = EVP_sha384(); digest_size = 48; break;
		case SHA512: hash_engine = EVP_sha512(); digest_size = 64; break;
		case MD5:    hash_engine = EVP_md5();    digest_size = 16; break;
		default:     return -1;
	}

	u_int32_t result_size = digest_size * 2;

	unsigned char *digest = HMAC(hash_engine, key, key_size, (unsigned char *)data, size, NULL, NULL);

	for(int i = 0; i < digest_size; i++) {
		sprintf(&target[i * 2], "%02x", (unsigned int)digest[i]);
	}
	target[result_size] = '\0';

	return result_size;
}

/*
int main() {
	hmac_engine_t engine = SHA512;
	char mdString[64 * 2 + 1];

	printf("%d\n", wrap_HMAC(engine, "0", 1, "testing!", 8, mdString));
	printf("--%s--\n", mdString);

	return 0;
}
*/
