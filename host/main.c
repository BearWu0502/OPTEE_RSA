// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 */

#include <err.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <acipher_ta.h>

static void usage(int argc, char *argv[])
{
	const char *pname = "acipher";

	if (argc)
		pname = argv[0];

	fprintf(stderr, "usage: %s <key_size> <string to encrypt>\n", pname);
	exit(1);
}

static void get_args(int argc, char *argv[], size_t *key_size, void **inbuf,
		     size_t *inbuf_len)
{
	char *ep;
	long ks;

	if (argc != 3) {
		warnx("Unexpected number of arguments %d (expected 2)",
		      argc - 1);
		usage(argc, argv);
	}

	ks = strtol(argv[1], &ep, 0);
	if (*ep) {
		warnx("cannot parse key_size \"%s\"", argv[1]);
		usage(argc, argv);
	}
	if (ks < 0 || ks == LONG_MAX) {
		warnx("bad key_size \"%s\" (%ld)", argv[1], ks);
		usage(argc, argv);
	}
	*key_size = ks;

	*inbuf = argv[2];
	*inbuf_len = strlen(argv[2]);
}

static void teec_err(TEEC_Result res, uint32_t eo, const char *str)
{
	errx(1, "%s: %#" PRIx32 " (error origin %#" PRIx32 ")", str, res, eo);
}

int main(int argc, char *argv[])
{
	TEEC_Result res;
	uint32_t eo;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	size_t key_size;
	void *inbuf;
	size_t inbuf_len;
	size_t n;
	const TEEC_UUID uuid = TA_ACIPHER_UUID;
	
	char *p[] = {"RSA","1024","jalkdsfdjlkah"};
	char *ciph;
	uint32_t ciph_len;
	char info[64] = "Hi, this is server.";
	uint32_t info_len = sizeof(info);
	char hash[64];
	uint32_t hash_len = sizeof(hash);
	char sign[256];
	uint32_t sign_len = sizeof(sign);
	uint8_t *exp;
	uint32_t explen;
	uint8_t *mod;
	uint32_t modlen;

	get_args(3, p, &key_size, &inbuf, &inbuf_len);

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res)
		errx(1, "TEEC_InitializeContext(NULL, x): %#" PRIx32, res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &eo);
	if (res)
		teec_err(res, eo, "TEEC_OpenSession(TEEC_LOGIN_PUBLIC)");

	/* Generate rsa key pair */

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
	op.params[0].value.a = key_size;
	
	printf("==== first malloc : exponent ====\nsize: %d\n", key_size);
	op.params[1].tmpref.buffer = malloc(key_size);
	
	printf("==== second malloc : modulus ====\nsize: %d\n", key_size);
	op.params[2].tmpref.buffer = malloc(key_size);
	
	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_GEN_KEY, &op, &eo);
	if (res)
		teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_GEN_KEY)");
	
	explen = op.params[1].tmpref.size;
	exp = (uint8_t *)op.params[1].tmpref.buffer;
	modlen = op.params[2].tmpref.size;
	mod = (uint8_t *)op.params[2].tmpref.buffer;
	
	printf("exp: %" PRIu8 " size = %" PRId32 "\n", exp, explen);
	printf("mod: %" PRIu8 " size = %" PRId32 "\n", mod, modlen);
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = info;
	op.params[0].tmpref.size = info_len;
	
	op.params[1].tmpref.buffer = hash;
	op.params[1].tmpref.size = hash_len;
	
	printf("info: %s size = %" PRId32 "\n",
			op.params[0].tmpref.buffer, op.params[0].tmpref.size);
	
	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_HASH, &op, &eo);
	if (res)
		teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_HASH)");
	
	hash_len = op.params[1].tmpref.size;
	printf("hash: %s hash_size = %" PRId32 "\n", hash, hash_len);
		
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = hash;
	op.params[0].tmpref.size = hash_len;
	
	op.params[1].tmpref.buffer = sign;
	op.params[1].tmpref.size = sign_len;
	
	printf("hash: %s hash_size = %" PRId32 "\n",
			op.params[0].tmpref.buffer, op.params[0].tmpref.size);
	
	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_SIGN, &op, &eo);
	if (res)
		teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_SIGN)");
	
	sign_len = op.params[1].tmpref.size;
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT);
	op.params[0].tmpref.buffer = hash;
	op.params[0].tmpref.size = hash_len;
	
	op.params[1].tmpref.buffer = sign;
	op.params[1].tmpref.size = sign_len;
	
	op.params[2].tmpref.buffer = exp;
	op.params[2].tmpref.size = explen;
	op.params[3].tmpref.buffer = mod;
	op.params[3].tmpref.size = modlen;
	
	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_VERIFY, &op, &eo);
	if (res)
		teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_VERIFY)");
	else printf("Verify Succeed!\n");
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_INPUT, 
					 TEEC_MEMREF_TEMP_INPUT);
	op.params[0].tmpref.buffer = inbuf;
	op.params[0].tmpref.size = inbuf_len;
	
	op.params[2].tmpref.buffer = exp;
	op.params[2].tmpref.size = explen;
	op.params[3].tmpref.buffer = mod;
	op.params[3].tmpref.size = modlen;
	
	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_ENCRYPT, &op, &eo);
	if (eo != TEEC_ORIGIN_TRUSTED_APP || res != TEEC_ERROR_SHORT_BUFFER)
		teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_ENCRYPT)");

	printf("==== third malloc : cipher ====\n");
	printf("size: %" PRId32 "\n", op.params[1].tmpref.size);
	op.params[1].tmpref.buffer = malloc(op.params[1].tmpref.size);
	if (!op.params[1].tmpref.buffer)
		err(1, "Cannot allocate out buffer of size %zu",
		    op.params[1].tmpref.size);

	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_ENCRYPT, &op, &eo);
	if (res)
		teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_ENCRYPT)");

	printf("Encrypted buffer: ");
	ciph = (char *)op.params[1].tmpref.buffer;
	printf("%s\n", ((char *)op.params[1].tmpref.buffer));
	
	ciph_len = strlen(ciph);
	
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = ciph;
	op.params[0].tmpref.size = ciph_len;

	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_DECRYPT, &op, &eo);
	if (eo != TEEC_ORIGIN_TRUSTED_APP || res != TEEC_ERROR_SHORT_BUFFER)
		teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_DECRYPT)");
	
	printf("==== fourth malloc : plain ====\n");
	printf("size: %" PRId32 "\n", op.params[1].tmpref.size);
	op.params[1].tmpref.buffer = malloc(op.params[1].tmpref.size);
	if (!op.params[1].tmpref.buffer)
		err(1, "Cannot allocate out buffer of size %zu",
		    op.params[1].tmpref.size);
	
	res = TEEC_InvokeCommand(&sess, TA_ACIPHER_CMD_DECRYPT, &op, &eo);
	if (res)
		teec_err(res, eo, "TEEC_InvokeCommand(TA_ACIPHER_CMD_DECRYPT)");

	printf("Decrypted buffer: ");
	printf("%s\n", (char *)op.params[1].tmpref.buffer);
	
	return 0;
}
